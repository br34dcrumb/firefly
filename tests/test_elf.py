import pytest

from firefly import elf

from elfbuild import ET_DYN, build_elf


def test_hardened_dynamic_executable():
    info = elf.parse(build_elf(etype=ET_DYN, interp="/lib/ld.so", nx=True, relro="full", pie_flag=True, needed=["libc.so.6"], imports=["accept"], canary=True))
    assert info.nx and info.pie and info.relro == "full" and info.has_stack_canary
    assert info.needed == ["libc.so.6"] and "accept" in info.imported_functions


def test_unhardened_static_executable():
    info = elf.parse(build_elf(etype=2, nx=False, imports=["gets", "strcpy"]))
    assert not info.nx and not info.pie and info.relro == "none" and not info.has_stack_canary


def test_shared_library_is_not_pie():
    info = elf.parse(build_elf(etype=ET_DYN, nx=True, relro="partial", soname="libfoo.so.1"))
    assert info.etype == ET_DYN and info.interp is None and not info.pie and info.relro == "partial"
    assert info.soname == "libfoo.so.1"


def test_needed_resolves_via_vaddr_mapping():
    # DT_STRTAB is a vaddr; resolution must map it through PT_LOAD.
    info = elf.parse(build_elf(needed=["libc.so.6", "libssl.so.1.1", "libdl.so.2"]))
    assert info.needed == ["libc.so.6", "libssl.so.1.1", "libdl.so.2"]


def test_symtab_means_not_stripped():
    assert elf.parse(build_elf(with_symtab=True)).stripped is False
    assert elf.parse(build_elf(with_symtab=False)).stripped is True


@pytest.mark.parametrize("data", [b"", b"not an elf", b"\x7fELF" + b"\x00" * 8, b"\x7fELF\x09\x01" + b"\x00" * 58])
def test_malformed_is_rejected(data):
    with pytest.raises(elf.ElfError):
        elf.parse(data)
