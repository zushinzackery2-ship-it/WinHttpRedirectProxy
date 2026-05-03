"""
Test the FField::Name offset validation algorithm with mock data.

The algorithm: walk Guid chain (A,B,C,D), read ComparisonIndex at each
candidate offset. If all 4 are the same -> REJECT the offset.

This simulates what happens when the Name offset is wrong by 4 bytes:
- At the CORRECT offset: each FField has a different ComparisonIndex
- At a WRONG offset: all FFields read the same value (e.g., from a
  padding field or a pointer that's the same for all instances)
"""

def validate_name_offset(comp_indices):
    """
    Returns True if the offset is valid (names are diverse),
    False if all names are the same (offset is wrong).

    Matches the C++ logic: walk Guid chain, read raw ComparisonIndex.
    If 3+ fields all have the same CI -> REJECT.
    """
    valid = [c for c in comp_indices if c is not None]
    if len(valid) < 3:
        return True  # Can't validate, accept
    unique = len(set(valid))
    return unique > 1


# Test case 1: Correct offset - each field has different ComparisonIndex
# Guid.A=0xA, Guid.B=0xB, Guid.C=0xC, Guid.D=0xD
test_correct = [0xA, 0xB, 0xC, 0xD]
assert validate_name_offset(test_correct) == True, "Should accept correct offset"

# Test case 2: Wrong offset - all fields read the same value
# (e.g., reading from a padding field that's 0 for all FFields)
test_wrong_same = [0x3299, 0x3299, 0x3299, 0x3299]
assert validate_name_offset(test_wrong_same) == False, "Should reject all-same offset"

# Test case 3: Wrong offset - all fields read 0 (null padding)
test_wrong_zero = [0, 0, 0, 0]
assert validate_name_offset(test_wrong_zero) == False, "Should reject all-zero offset"

# Test case 4: Partial match - 3 same, 1 different (edge case)
test_partial = [0x3299, 0x3299, 0x3299, 0xA]
assert validate_name_offset(test_partial) == True, "Should accept if at least 2 different"

# Test case 5: Only 2 fields available (too few to validate)
test_few = [0x3299, 0x3299]
assert validate_name_offset(test_few) == True, "Should accept if too few fields"

# Test case 6: Some None values
test_none = [0x3299, None, 0x3299, 0x3299]
assert validate_name_offset(test_none) == False, "Should reject if remaining are all same"

# Test case 7: All None
test_all_none = [None, None, None, None]
assert validate_name_offset(test_all_none) == True, "Should accept if all None"

print("All tests passed!")

# Now simulate the actual scenario:
# The dumper tests offsets 0x00, 0x04, 0x08, ..., 0x3C
# For each offset, it reads ComparisonIndex from Guid.A, B, C, D
# At the WRONG offset (e.g., 0x24), all 4 read the same value
# At the CORRECT offset (e.g., 0x20), each reads a different value

print("\n=== Simulated offset scan ===")
print("Offset | A     | B     | C     | D     | Unique | Result")
print("-------+-------+-------+-------+-------+--------+-------")

# Simulate: correct Name offset is 0x20, wrong offsets read same value
correct_ci = {0x20: [0x100, 0x200, 0x300, 0x400]}  # Different CIs at correct offset

for off in range(0, 0x40, 4):
    if off == 0x20:
        cis = correct_ci[off]
    elif off in [0x00, 0x08, 0x10, 0x18]:
        # These offsets read pointer fields (VTable, Class, Owner, Next)
        # which are different for each FField
        cis = [0x14A70010 + off, 0x14E69C080, 0x7FF4DE1874E0, 0x7FF4DE187528]
    else:
        # Wrong offset reads same value for all fields
        cis = [0x3299, 0x3299, 0x3299, 0x3299]

    valid = [c for c in cis if c is not None and c > 0]
    unique = len(set(valid))
    accepted = validate_name_offset(cis)
    result = "ACCEPT" if accepted else "REJECT"

    ci_strs = ["0x%04X" % c for c in cis]
    print("  0x%02X | %s | %s | %s | %s |   %d    | %s" % (
        off, ci_strs[0], ci_strs[1], ci_strs[2], ci_strs[3], unique, result))
