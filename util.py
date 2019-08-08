import itertools

from binaryninja import MediumLevelILOperation


def create_named_function(bv, address, name, comment=None):
    """Create and name a function. Add an optional comment."""
    bv.add_function(address)
    func = bv.get_function_at(address)
    func.name = name
    if comment is not None:
        func.set_comment_at(address, comment)


def get_store_offset(inst):
    """Get the store offset for an MLIL store instuction."""
    assert inst.operation == MediumLevelILOperation.MLIL_STORE

    offset = 0
    inst = inst.dest
    while inst.operation != MediumLevelILOperation.MLIL_VAR:
        if inst.operation == MediumLevelILOperation.MLIL_ADD:
            assert inst.right.value.is_constant
            offset += inst.right.value.value
            inst = inst.left
        else:
            raise RuntimeError(inst)
    return offset


def get_stores_by_offset(function, variable):
    """Get a list of all stores that occurred at an offset from the given
        variable.

    Before finding stores, this function will try to identify potential aliases
    by performing a breadth-first search of all variable defs and uses. Note
    that this is a flow-insensitive analysis, and assumes only a single store
    per offset.

    :param function: binaryninja.function.Function representing the function
        to analyze.
    :param variable: binaryninja.function.Variable representing the base
        address for store operations to find.
    :return: Dictionary of stores, mapping offsets to the value stored at that
        offset. {int: MediumLevelILInstruction, int: MediumLevelILInstruction}.
    """
    stores = {}
    aliases = set([variable])
    mlil = function.medium_level_il

    # Follow the use-def chain to build an initial list of aliases for this
    # variable. If the definition was an assignment from another variable, record
    # the source variable as an alias and add it to the set of variables to search.
    defs = mlil.get_var_definitions(variable)
    while len(defs) > 0:
        inst = mlil[defs.pop(0)]
        if (inst.operation == MediumLevelILOperation.MLIL_SET_VAR and
                inst.src.operation == MediumLevelILOperation.MLIL_VAR):
            src = inst.src.src
            aliases.add(src)
            defs += mlil.get_var_definitions(src)

    # Now follow the def-use chain for the variable and all known aliases in
    # order to find additional aliases. This check should always find a
    # superset of the currently known aliases, since the def-use chain will
    # include any of the SET_VAR instructions we used to construct the initial
    # alias set.
    uses = [mlil.get_var_uses(var) for var in aliases]
    uses = list(itertools.chain.from_iterable(uses))
    while len(uses) > 0:
        inst = mlil[uses.pop(0)]
        if (inst.operation == MediumLevelILOperation.MLIL_SET_VAR and
                inst.src.operation == MediumLevelILOperation.MLIL_VAR):
            dest = inst.dest
            aliases.add(dest)
            uses += mlil.get_var_uses(dest)

    # We now have most (hopefully all) aliases for the given variable. Record
    # all stores that occurred using one of the aliases as the base address.
    for var in aliases:
        for use in mlil.get_var_uses(var):
            inst = mlil[use]
            if (inst.operation == MediumLevelILOperation.MLIL_STORE and
                    inst.src != var):
                offset = get_store_offset(inst)
                stores[offset] = inst.src

    return stores
