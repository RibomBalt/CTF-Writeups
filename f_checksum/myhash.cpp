#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mpi.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace fs = std::filesystem;

constexpr size_t BLOCK_SIZE = 1024 * 1024;
constexpr int NPROC = 8;
// constexpr size_t SHA512_BLOCK_SIZE = 128;

#ifdef debug_myhash
    constexpr int DEBUG = 1;
#else
    constexpr int DEBUG = 0;
#endif

// void checksum(uint8_t *data, size_t len, uint8_t *obuf);
void print_checksum(std::ostream &os, uint8_t *md, size_t len);

void print_debug(char *msg, int rank) {
    if (DEBUG) {
        std::cout << "DEBUG: rank:" << rank << ":: " << msg << std::endl;
    }
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);
    
    int rank, nprocs;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nprocs);

    // initialize
    if (argc < 3) {
        if (rank == 0)
            std::cout << "Usage: " << argv[0] << " <input_file> <output_file>"
                    << std::endl;
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    fs::path input_path = argv[1];
    fs::path output_path = argv[2];

    auto total_begin_time = std::chrono::high_resolution_clock::now();

    // traverse every file in the path
    auto file_size = fs::file_size(input_path);

    unsigned int num_block = file_size / BLOCK_SIZE;
    unsigned int last_line_block_id = ((num_block - 1) >> 3) << 3;
    if (rank == 0)
        std::cout << input_path << " size: " << file_size
            << " num_block: " << num_block 
            << " last_line_block_id: " << last_line_block_id << std::endl;

    auto begin_time = std::chrono::high_resolution_clock::now();

    //  Init MPI IO
    MPI_File fh;
    MPI_Info info;

    // MPI_Info_set(info, "romio_cb_read", "enable");
    // MPI_Info_set(info, "striping_unit", "1048576");
    info = MPI_INFO_NULL;

    MPI_File_open(MPI_COMM_WORLD, argv[1], MPI_MODE_RDONLY, info, &fh);

    // file views
    MPI_Aint lb, extent;
    MPI_Datatype etype, filetype, contig;
    MPI_Offset disp;

    MPI_Type_contiguous(BLOCK_SIZE, MPI_UINT8_T, &contig);
    extent = nprocs * BLOCK_SIZE;
    MPI_Type_create_resized(contig, lb, extent, &filetype);
    MPI_Type_commit(&filetype);
    disp = rank * BLOCK_SIZE;
    etype = MPI_UINT8_T;
    MPI_File_set_view(fh, disp, etype, filetype, "native", info);

    // init memory of md, init ctx
    uint8_t prev_md[SHA512_DIGEST_LENGTH]{};
    uint8_t this_md[SHA512_DIGEST_LENGTH]{};
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD *sha512 = EVP_MD_fetch(nullptr, "SHA512", nullptr);
    
    MPI_Status status;
    unsigned int len = 0;

    // first calculate empty file sha512 for first block
    if (rank == 0){
        SHA512(nullptr, 0, prev_md);
        // debug
        #ifdef debug_myhash
            std::cout << "Empty hash: ";
            print_checksum(std::cout, prev_md, SHA512_DIGEST_LENGTH);
            std::cout << std::endl;
        #endif
    }

    #ifdef debug_myhash
    char msg[1024]{};
    #endif

    uint8_t data_buf[BLOCK_SIZE];
    // iterate over each line of blocks
    for (int block_line_id=0; block_line_id < num_block; block_line_id+=8){
        // prepare data buffer
        if (block_line_id == last_line_block_id){
            memset(data_buf, 0, BLOCK_SIZE);
        // read data
        if (block_line_id < last_line_block_id) {
            MPI_File_read(fh, data_buf, BLOCK_SIZE, MPI_UINT8_T, &status);
            
            #ifdef debug_myhash
                if (block_line_id <= 3 * 8) {
                    std::cout << "id: " << (rank + block_line_id) << " content: ";
                    print_checksum(std::cout, data_buf, 256);
                    std::cout << std::endl;
                }

            sprintf(msg, "read data:: block_line_id: %d, rank: %d", block_line_id, rank);
            print_debug(msg, rank);
            
            #endif

        } else {
            if (rank < (num_block & 7) - 1) {
                // still blocks of data
                MPI_File_read(fh, data_buf, BLOCK_SIZE, MPI_UINT8_T, MPI_STATUS_IGNORE);

            } else if (rank == (num_block & 7) - 1) {
                // last block of data
                MPI_File_read(fh, data_buf, ((file_size - 1) & 0xfffffUL) + 1, MPI_UINT8_T, MPI_STATUS_IGNORE);
                #ifdef debug_myhash
                    std::cout << "final chunk remnant: ";
                    print_checksum(std::cout, data_buf, 32);
                    std::cout << " ... ";
                    print_checksum(std::cout, data_buf + (file_size & 0xfffffUL), 32);
                    std::cout << std::endl;
                #endif

            } else {
                // no more data
                break;
            }

        }
        // calc sha512(chunk)
        EVP_DigestInit_ex(ctx, sha512, nullptr);
        EVP_DigestUpdate(ctx, data_buf, BLOCK_SIZE);
        
        // receive md from previous
        // NOTE: should be non-blocking, check whether 
        MPI_Request *recv_req, send_req;
        if (block_line_id == 0 && rank == 0) {
            [[unlikely]]
            // directly ;
            #ifdef debug_myhash
                std::cout << "first prev_md: " ;
                print_checksum(std::cout, prev_md, SHA512_DIGEST_LENGTH);
                std::cout << std::endl;
            #endif
            ;
        } else {
            [[likely]]
            
            #ifdef debug_myhash
            sprintf(msg, "before recv:: block_line_id: %d, rank: %d", block_line_id, rank);
            print_debug(msg, rank);
            #endif

            MPI_Recv(prev_md, SHA512_DIGEST_LENGTH, MPI_UINT8_T, (rank - 1) & 7, 
                rank + block_line_id - 1, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

            #ifdef debug_myhash
            sprintf(msg, "after recv:: block_line_id: %d, rank: %d", block_line_id, rank);
            print_debug(msg, rank);
            #endif
        }
        EVP_DigestUpdate(ctx, prev_md, SHA512_DIGEST_LENGTH);
        EVP_DigestFinal_ex(ctx, this_md, &len);

        #ifdef debug_myhash
            std::cout << "block_id " << (rank + block_line_id) << " results: ";
            print_checksum(std::cout, this_md, SHA512_DIGEST_LENGTH);
            std::cout << std::endl;
        #endif

        if (block_line_id + rank < num_block - 1) {
            #ifdef debug_myhash
            sprintf(msg, "before send:: block_line_id: %d, rank: %d", block_line_id, rank);
            print_debug(msg, rank);
            #endif
            
            MPI_Send(this_md, SHA512_DIGEST_LENGTH, MPI_UINT8_T, (rank + 1) & 7,
                rank + block_line_id, MPI_COMM_WORLD);

            #ifdef debug_myhash
            sprintf(msg, "after send:: block_line_id: %d, rank: %d", block_line_id, rank);
            print_debug(msg, rank);
            #endif

        } else {
            // luckly to be the final chunk
            auto end_time = std::chrono::high_resolution_clock::now();

            std::cout << "checksum: ";
            print_checksum(std::cout, this_md, SHA512_DIGEST_LENGTH);
            std::cout << std::endl;

            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - begin_time);
            std::cout << "checksum time cost: " << std::dec << duration.count() << "ms"
              << std::endl;

            std::ofstream output_file(output_path);
            print_checksum(output_file, this_md, SHA512_DIGEST_LENGTH);
        }


    }

    EVP_MD_CTX_free(ctx);
    EVP_MD_free(sha512);

    // Finalize MPI
    MPI_File_close(&fh);
    // MPI_Info_free(&info);
    MPI_Finalize();

    return 0;
}
}


void print_checksum(std::ostream &os, uint8_t *md, size_t len) {
  for (int i = 0; i < len; i++) {
    os << std::setw(2) << std::setfill('0') << std::hex
       << static_cast<int>(md[i]);
  }
}