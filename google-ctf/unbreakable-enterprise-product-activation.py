#!/usr/bin/env python

import angr 

p = angr.Project("./re-elf", load_options={"auto_load_libs":False})

start_address = 0x4005BD
end_address   = 0x400722
flag_address  = 0x6042C0
sz = 0x43

s = p.factory.blank_state(addr = start_address)
s.mem[flag_address:] = s.BV("ans", 8 * sz)

for i in xrange(sz):
    b = s.memory.load(flag_address + i, 1)
    s.add_constraints(b >= 0x20, b <= 0x7e)

pg = p.factory.path_group(s, immutable = False)
pg.explore(find = end_address)
found_state = pg.found[0].state
sol = found_state.se.any_str(found_state.memory.load(flag_address, sz))

print sol
