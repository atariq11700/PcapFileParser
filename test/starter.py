def main():
    # Open a file for reading a bit at a time
    fp = open("data_0.pcap", "rb")

    # Read the magic number to set the byte order
    magic_num = fp.read(4)
    byte_order = "little" if magic_num == b'\xd4\xc3\xb2\xa1' else "big"

    # Process the rest of the file header
    ver_maj = int.from_bytes(fp.read(2), byte_order)
    ver_min = int.from_bytes(fp.read(2), byte_order)
    tz = int.from_bytes(fp.read(4), byte_order)
    sig_figs = int.from_bytes(fp.read(4), byte_order)
    snap_len = int.from_bytes(fp.read(4), byte_order)
    network = int.from_bytes(fp.read(4), byte_order)

    print("Pcap Version: " + str(ver_maj) + "." + str(ver_min))
    print("Time Zone: " + str(tz))
    print("Significant Figures: " + str(sig_figs))
    print("Snap Length: " + str(snap_len))
    print("Network Type: " + str(network))

    # packet counter
    packet_id = 1

    # Read the file a packet at a time until done
    # This processes the pcap header that is stored with each packet
    while True:
        # Timestamp seconds
        ts_sec = int.from_bytes(fp.read(4), byte_order)
        # check to see if we've reached the end of the file
        if ts_sec == 0:
            break

        # Timestamp microseconds
        ts_usec = int.from_bytes(fp.read(4), byte_order)

        # Length of captured bytes. This is less than actual length
        # if only a portion (like headers) are captured
        incl_len = int.from_bytes(fp.read(4), byte_order)

        # Actual length of the packet
        orig_len = int.from_bytes(fp.read(4), byte_order)

        print("Packet #" + str(packet_id))
        print("\tUNIX Time: " + str(ts_sec) + "." + f"{ts_usec:06d}")
        print("\tBytes Captured/Actual: " + str(incl_len) + "/" + str(orig_len))
        packet_id += 1

        # Read the actual network data. You may want to think
        # about doing something with this
        packet = fp.read(incl_len)

    # close the file
    fp.close()


if __name__ == "__main__":
    main()