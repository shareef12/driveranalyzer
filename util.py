from binaryninja import MediumLevelILOperation


def create_named_function(bv, address, name, comment=None):
    """Create and name a function. Add an optional comment."""
    bv.add_function(address)
    func = bv.get_function_at(address)
    func.name = name
    if comment is not None:
        func.set_comment_at(address, comment)


def get_store_offset(inst):
    """Get the store offset."""
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
    """Get a list of all stores that occurred at an offset from the
        given variable.

    Perform a breadth-first search of all variable defs and uses. Traverse the
    use-def and def-use chain to handle pointer aliasing and record the offset
    and source of all stores. Assumes that there is only a single store per
    offset.

    :return: Dictionary of stores. {offset: value, offset: value}
    """
    stores = {}
    mlil = function.medium_level_il

    # Follow the use-def chain to get a list of all definitions.
    # Add these to the set of uses to search later for stores, since
    # a store could occur from either the original definition or the
    # current one we're searching.
    uses = mlil.get_var_uses(variable)
    defs = mlil.get_var_definitions(variable)
    while len(defs) > 0:
        mlil_idx = defs.pop(0)
        uses.append(mlil_idx)
        inst = mlil[mlil_idx]
        if inst.operation == MediumLevelILOperation.MLIL_SET_VAR and \
                inst.src.operation == MediumLevelILOperation.MLIL_VAR:
            src = inst.src.src
            defs += mlil.get_var_definitions(src)

    # Follow the def-use chain for all defs while maintaining a set of visited uses
    visited = set()
    while len(uses) > 0:
        inst = mlil[uses.pop(0)]
        if inst.operation == MediumLevelILOperation.MLIL_SET_VAR:
            for use in mlil.get_var_uses(inst.dest):
                if use not in visited:
                    visited.add(use)
                    uses.append(use)

        # Record stores
        elif inst.operation == MediumLevelILOperation.MLIL_STORE:
            offset = get_store_offset(inst)
            stores[offset] = inst.src

    return stores
