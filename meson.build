project('prkit', 'c')
add_project_arguments('-D_GNU_SOURCE', language : 'c')

prkit = library('prkit', ['src/prkit.c'], install : true)
executable('walk', ['demo/walk.c'], link_with : [prkit])
executable('monitor', ['demo/monitor.c'], link_with : [prkit])
