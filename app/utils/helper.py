def merge_sorted_uuid_segments(sender_id, receiver_id):
    s1, s2 = sender_id.split("-")[-1], receiver_id.split("-")[-1]
    return "_".join(sorted([s1, s2]))
