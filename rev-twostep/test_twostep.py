import angr, monkeyhex, claripy

proj = angr.Project('twostep')

flag_chars = claripy.Concat(*[claripy.BVS('flag_%d' % i, 8) for i in range(5)])

state = proj.factory.call_state(0x4016c1)

state.memory.store(0x404310, (2).to_bytes(4, 'little'))

@proj.hook(0x4018ca, length=12)
def hook_rax(state):
    state.memory.store(state.regs.rbp - 0xd8, flag_chars)

simgr = proj.factory.simgr(state)
# simgr.explore(find=lambda state: state.solver.is_true(state.regs.rip == 0x4016c0) and state.solver.is_false(state.regs.eax == 0), 
#               avoid= lambda state: state.solver.is_true(state.regs.rip == 0x4016c0) and state.solver.is_true(state.regs.eax == 0))

simgr.explore(find=0x401958, avoid=0x401932)

print(simgr.found[0].solver.eval(flag_chars).to_bytes(0x8,"big"))
print(simgr.found[0].memory.hex_dump(0x7fffffffffeff1d, 0x80))