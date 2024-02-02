import numpy as np
import os
import logging
import asyncio

# from pprint import pprint
import time

# import memray
import ray
from ray.util.placement_group import (
    placement_group,
    placement_group_table,
    remove_placement_group,
)
from ray.util.scheduling_strategies import PlacementGroupSchedulingStrategy


os.makedirs('outputs', exist_ok=True)
logger = logging.getLogger("ray")
logger.setLevel(logging.INFO)
if os.path.isdir('./logs'):
    logger.addHandler(logging.FileHandler("./logs/ray.extra.log"))

if 'RAY_CLUSTER_ADDR' in os.environ:
    ray.init(address=f"{os.environ['RAY_CLUSTER_ADDR']}")
elif 'LOCAL_TEST' in os.environ:
    ray.init(num_cpus=16)
else:
    raise RuntimeError("ray cluster error")


@ray.remote(num_cpus=4)
class Calcer():
    def __init__(self, inode, nnode = 4, last_node=None) -> None:
        self.inode = inode
        self.nnode = nnode

        self.weight_loaded = False
        self.i_task = -1
        self.arr_cache = {}

        self.last_node = last_node

        # self.log('finish init')

        # self.log(f'local directory: {os.getcwd()}')
        # self.log(f'local hostname: {os.popen("hostname").read()}')

        
    
    def log(self, msg):
        logger.info(f'inode {self.inode}: {msg}')

    def load_weight(self):
        # self.log('start load weight')
        self.weight = np.load(f"weights/weight_{self.inode:d}.npy")
        self.weight_loaded = True
        # self.log(f'end load weight, {self.weight.shape}')

        return True

    def matmul_io(self, i_task:int):
        if self.last_node is None:
            # self.log(f'{i_task} start load arr')
            self.i_task = i_task
            arr = np.load(f"inputs/input_{i_task}.npy")
            # self.log(f"{i_task} end load arr {arr.shape}")
        else:
            # self.log(f"{i_task} start req arr")
            arr = ray.get(self.last_node.matmul_pipeline.remote(i_task))
            # self.log(f"{i_task} end req arr {arr.shape}")

        return arr


    def matmul_pipeline(self, i_task:int, dump=False):
        # IO
        arr = self.matmul_io(i_task=i_task)

        # matmul & relu
        # self.log(f'{i_task} start calc, {arr.shape}x{self.weight.shape}')
        arr = np.matmul(arr, self.weight)
        arr[arr < 0] = 0
        # self.log(f'{i_task} end calc')

        if dump:
            # self.log(f"{i_task} start dump arr")
            np.save(f"outputs/output_{i_task}.npy", arr)
            # self.log(f"{i_task} end dump arr")

            return i_task

        # arr_ref = ray.put(arr)
        # return arr_ref
        return arr
    

    def matmul_relu(self, i_task, arr, weight):

        self.i_task = i_task
        # self.log(f"{i_task} matmul start")
        new_arr = np.matmul(arr, self.weight)
        # self.log(f"{i_task} relu start")
        new_arr[new_arr < 0] = 0.
        # self.log(f"{i_task} matmul finish")

        return new_arr
    
    def load_arr(self, i_task:int):

        # self.log(f"{i_task} start load arr")
        self.i_task = i_task
        arr = np.load(f"inputs/input_{i_task}.npy")
        # self.log(f"{i_task} end load arr {arr.shape}")
        return arr
    
    def dump_arr(self, i_task:int, arr):

        # self.log(f"{i_task} start dump arr")
        self.i_task = i_task
        np.save(f'outputs/output_{i_task}.npy', arr)
        # self.log(f"{i_task} end dump arr")
        
        return i_task
    
    def get_hostname(self):
        return os.popen('hostname').read().strip()
    
    def set_lastnode(self, node):
        self.last_node = node

HEAD_NODE_HOSTNAME = os.popen('hostname').read().strip()
nodes = [placement_group([{'CPU': 4}], strategy='STRICT_PACK') for i in range(4)]

calcers = []
for inode in range(4):
    if inode == 0:
        c = Calcer.options(
        scheduling_strategy=PlacementGroupSchedulingStrategy(
                placement_group=nodes[inode],
            ), 
            max_concurrency=4,
        ).remote(inode=inode, last_node=None)
    else:
        c = Calcer.options(
        scheduling_strategy=PlacementGroupSchedulingStrategy(
                placement_group=nodes[inode],
            ),
            max_concurrency=4,
        ).remote(inode=inode, last_node=calcers[inode - 1])

    calcers.append(c)

# hostnames = ray.get([c.get_hostname.remote() for c in calcers])
# logger.info(f"hostnames: {hostnames}; HEAD_HOST: {HEAD_NODE_HOSTNAME}")
# I_head = hostnames.index(HEAD_NODE_HOSTNAME)
# calcers[-1], calcers[I_head] = calcers[I_head], calcers[-1]

weights_f = [c.load_weight.remote() for c in calcers]
# ray.get(weights_f)

MAX_TASK = 100

dump_res = {}
for i_task in range(MAX_TASK + 4):
    if i_task < MAX_TASK:
        dump_res[i_task] = calcers[-1].matmul_pipeline.remote(i_task, dump=True)
    
    # if i_task >= 4:
    #     ray.get(dump_res[i_task - 4])


logger.info('Schedule over?')
ray.get([dump_res[i] for i in range(MAX_TASK)])

# ray.get(dump_indexs)

# arr_pipeline = [None for i in range(5)]
# for i_task in range(MAX_TASK):
#     arr_pipeline[0] = calcers[0].load_arr.remote(i_task)

#     for i_step in range(4):
#         arr_pipeline[i_step + 1] = calcers[i_step].matmul_relu.remote(i_task, arr_pipeline[i_step], weights_f[i_step])
#     final_itask = calcers[3].dump_arr.remote(i_task, arr_pipeline[4])

#     if i_task == MAX_TASK - 1:
#         ray.get(final_itask)
#         break

#     # del arr

# ray.get(weights_f)

