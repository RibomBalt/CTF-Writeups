const sleep = ms => new Promise(r => setTimeout(r, ms));

get_tile = () => {
    var all_tiles = document.querySelectorAll('div.Game-tile');
    var all_tile_text = Array.from(all_tiles).map((e)=>{
        let emo = e.innerText;
        switch(emo){
            case '🌊':
                return 0;
            case '⛵':
                return 2;
            case '💣':
                return 1;
        }
    })
    var cur_pos = all_tile_text.indexOf(2);
    var cur_x = Math.floor(cur_pos / 99);
    var cur_y = cur_pos % 99;
    return [all_tile_text, cur_x, cur_y]
}

right = async (nmax)=>{
    for(i=0; i<nmax; i++){
        var all_tile_text, cur_x, cur_y
        [all_tile_text, cur_x, cur_y] = get_tile();

        if (cur_y + 1 < 99 && all_tile_text[cur_x * 99 + cur_y + 1] != 1){
            console.log(`x=${cur_x},y=${cur_y}`)
            window.dispatchEvent(new KeyboardEvent('keydown', {'key': 'd'}));
            await sleep(10)

        }else{
            break;
        }
    }
}
left = async (nmax)=>{
    for(i=0; i<nmax; i++){
        var all_tile_text, cur_x, cur_y
        [all_tile_text, cur_x, cur_y] = get_tile();

        if (cur_y - 1 >= 0 && all_tile_text[cur_x * 99 + cur_y - 1] != 1){
            console.log(`x=${cur_x},y=${cur_y}`)
            window.dispatchEvent(new KeyboardEvent('keydown', {'key': 'a'}));
            await sleep(10)

        }else{
            break;
        }
    }
}
up = async (nmax)=>{
    for(i=0; i<nmax; i++){
        var all_tile_text, cur_x, cur_y
        [all_tile_text, cur_x, cur_y] = get_tile();

        if (cur_x - 1 >= 0 && all_tile_text[(cur_x - 1) * 99 + cur_y] != 1){
            console.log(`x=${cur_x},y=${cur_y}`)
            window.dispatchEvent(new KeyboardEvent('keydown', {'key': 'w'}));
            await sleep(10)

        }else{
            break;
        }
    }
}
down = async (nmax)=>{
    for(i=0; i<nmax; i++){
        var all_tile_text, cur_x, cur_y
        [all_tile_text, cur_x, cur_y] = get_tile();

        if (cur_x + 1 < 99 && all_tile_text[(cur_x + 1) * 99 + cur_y] != 1){
            console.log(`x=${cur_x},y=${cur_y}`)
            window.dispatchEvent(new KeyboardEvent('keydown', {'key': 's'}));
            await sleep(10)

        }else{
            break;
        }
    }
}

[TILE, cur_x, cur_y] = get_tile()
var next_target = TILE.indexOf(0);
target_x = Math.floor(next_target / 99);
target_y = 

[NEWTILE, cur_x, cur_y] = get_tile();
TILE[cur_x * 99 + cur_y] = 2;