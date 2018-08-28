#!/usr/bin/env python

import angr

p = angr.Project("./baby-re", load_options={"auto_load_libs":False})

start_address = 0x4006C6
end_address   = 0x4025CC
flag_address  = 0x603200
sz = 0xD

s = p.factory.blank_state(addr = start_address)
s.regs.rdi = flag_address
s.mem[flag_address:] = s.BV("ans", 8 * sz * 4)

for i in xrange(0, sz):
    b = s.memory.load(flag_address + (i*4), 4)
    s.add_constraints(b >= 0, b <= 0x7fffffff)

pg = p.factory.path_group(s, immutable = False)
pg.explore(find = end_address)   
found_state = pg.found[0].state
sol = found_state.se.any_str(found_state.memory.load(flag_address, sz*4))

flag = ''
for i in range(0, len(sol), 4): flag += sol[i:i+4][0]

print flag
