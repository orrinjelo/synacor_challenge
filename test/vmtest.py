import os
import io
import sys
import logging

sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..')))

from virtual_machine.VirtualMachine import VirtualMachine

log = logging.getLogger()

class Tests:

    def test_halt():
        # Test writing 5 A's with a halt 
        vm = VirtualMachine()

        sys.stdout = io.StringIO()
        vm.run(bytestr=b'\x13\x00A\x00\x13\x00A\x00\x13\x00A\x00\x13\x00A\x00\x13\x00A\x00\x00\x00')
        res = sys.stdout.getvalue()
        log.vomit(res)
        assert(res == 'AAAAA')

    def test_out():
        # Test writing Abc with noops and a halt
        vm = VirtualMachine()

        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x13\x00A\x00\x13\x00b\x00\x13\x00c\x00\x15\x00\x15\x00\x15\x00\x00\x00')
        res = sys.stdout.getvalue()
        log.vomit(res)
        assert(res == 'Abc')

    def test_noop():
        # No halt test
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x15\x00\x15\x00\x15\x00')
        res = sys.stdout.getvalue()
        log.vomit(res)
        assert(res == '')

    def test_set():
        # Set registers
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x01\x00\x00\x80\x02\x00\x01\x00\x01\x80\x02\x00\x00\x00')
        log.vomit(vm.registers)
        assert(vm.registers[0] == 2)
        assert(vm.registers[1] == 2)

    def test_push():
        # Push
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x02\x00\x04\x00\x00\x00')
        log.vomit(vm.stack)
        assert(vm.stack[0] == 4)

    def test_pop():
        # Pop
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x02\x00\x04\x00\x02\x00\x05\x00\x03\x00')
        log.vomit(vm.stack)
        assert(vm.stack[0] == 4)
        assert(len(vm.stack) == 1)

    def test_eq():
        # Eq
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x04\x00\x04\x00\x05\x00\x06\x00\x00\x00\x00\x02\x00\x02')
        log.vomit(vm.mem[:10])
        assert(vm.mem[4] == 1)

    def test_gt():
        # greater than
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x05\x00\x04\x00\x05\x00\x06\x00\x00\x00\x01\x02\x00\x02')
        log.vomit(vm.mem[:10])
        assert(vm.mem[4] == 1)

    def test_jmp():
        # jump
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x06\x00\xcf\x00\x01\x00\x06\x00\xff\x00\x00\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[6] == 0)
        assert(vm.pc == 0xd0)

    def test_jt():
        # jump non-zero
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x07\x00\x01\x00\xcf\x00\x01\x00\x07\x00\xff\x00\x00\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[7] == 0)
        assert(vm.pc == 0xd0)

    def test_jf():
        # jump zero
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x08\x00\x01\x00\xcf\x00\x01\x00\x07\x00\xff\x00\x00\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[7] == 0xff)
        assert(vm.pc == 7)

    def test_add():
        # add
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x09\x00\x07\x00\x04\x00\x05\x00\xcf\x00\x01\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[7] == 0xd0)

    def test_mult():
        # mult
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x0a\x00\x07\x00\x04\x00\x05\x00\x05\x00\x05\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[7] == 0x19)

    def test_mod():
        # mod
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x0b\x00\x07\x00\x04\x00\x05\x00\x10\x00\x05\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[7] == 1)

    def test_andb():
        # andb
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x0c\x00\x07\x00\x04\x00\x05\x00\x01\x00\x03\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[7] == 1)

    def test_orb():
        # or bitwise
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x0d\x00\x07\x00\x05\x00\x06\x00\x00\x00\x01\x00\x03\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[7] == 3)

    def test_not():
        # not
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x0e\x00\x04\x00\x04\x00\x00\x00\xff\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[4] == 0x7f00)

    def test_rmem():
        #rmem
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x0f\x00\x04\x00\x05\x00\x00\x00\x00\x00\xef\xbe')
        log.vomit(vm.mem[:10])
        assert(vm.mem[4] == 0xbeef)

    def test_wmem():
        #wmem
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x10\x00\x04\x00\x05\x00\x00\x00\x05\x00\xef\xbe')
        log.vomit(vm.mem[:10])
        assert(vm.mem[4] == 5)

    def test_call():
        #call
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x15\x00\x11\x00\x20\x00')
        log.vomit(vm.pc)
        log.vomit(vm.stack)
        assert(vm.pc == 0x0021)
        assert(vm.stack == [3])

    def test_ret():
        #ret
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x15\x00\x11\x00\x05\x00\x00\x00\x00\x00\x12\x00')
        log.vomit(vm.pc)
        log.vomit(vm.stack)
        assert(vm.pc == 4)
        assert(vm.stack == [])

    def test_in():
        #in
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x14\x00\x07\x00\x14\x00\x08\x00\x14\x00\x09\x00\x00\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[3] != 0)

    def run_all_tests():
        Tests.test_halt()
        Tests.test_set()
        Tests.test_push()
        Tests.test_pop()
        Tests.test_noop()
        Tests.test_eq()
        Tests.test_gt()
        Tests.test_jmp()
        Tests.test_jt()
        Tests.test_jf()
        Tests.test_add()
        Tests.test_mult()
        Tests.test_mod()
        Tests.test_andb()
        Tests.test_orb()
        Tests.test_not()
        Tests.test_rmem()
        Tests.test_wmem()
        Tests.test_call()
        Tests.test_ret()
        Tests.test_out()
        Tests.test_in()
        