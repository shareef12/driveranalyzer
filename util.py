from binaryninja import MediumLevelILOperation


def create_named_function(bv, address, name, comment=None):
    """Create and name a function. Add an optional comment."""
    bv.add_function(address)
    func = bv.get_function_at(address)
    func.name = name
    if comment is not None:
        func.set_comment_at(address, comment)


def get_store_offset_value(inst):
    """Get the store offset and constant source value.

    :return: Tuple of (offset, value)
    """

    value = inst.src.value.value

    offset = 0
    inst = inst.dest
    while inst.operation != MediumLevelILOperation.MLIL_VAR:
        if inst.operation == MediumLevelILOperation.MLIL_ADD:
            assert inst.right.value.is_constant
            offset += inst.right.value.value
            inst = inst.left
        else:
            raise RuntimeError(inst)

    return offset, value


def get_offset_stores(mlil, variable):
    """Get a list of all constant stores that occurred at an offset from the
        given variable.

    Perform a breadth-first search of all variable uses. Traverse the def-use
    chain and record the offset and source of all stores with a constant
    source.

    :return: List of tuples. [(offset, value), (offset, value)]
    """

    stores = []
    uses = mlil.get_var_uses(variable)
    while len(uses) > 0:
        use = mlil[uses[0]]
        uses = uses[1:]

        # Record constant stores
        if use.operation == MediumLevelILOperation.MLIL_STORE and use.src.value.is_constant:
            off, val = get_store_offset_value(use)
            stores.append((off, val))

        # Get new uses
        if use.operation == MediumLevelILOperation.MLIL_SET_VAR:
            dest = use.dest
            uses += mlil.get_var_uses(dest)

    return stores
