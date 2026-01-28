use proptest::prelude::*;

use dhcplease::DhcpPacket;

const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
const DHCP_FIXED_HEADER_SIZE: usize = 240;

fn valid_header() -> Vec<u8> {
    let mut packet = vec![0u8; DHCP_FIXED_HEADER_SIZE];
    packet[0] = 1;
    packet[1] = 1;
    packet[2] = 6;
    packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    packet
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]

    #[test]
    fn parse_never_panics_on_arbitrary_bytes(data: Vec<u8>) {
        let _ = DhcpPacket::parse(&data);
    }

    #[test]
    fn parse_never_panics_on_valid_header_with_random_options(
        options_data in prop::collection::vec(any::<u8>(), 0..512)
    ) {
        let mut packet = valid_header();
        packet.extend_from_slice(&options_data);
        let _ = DhcpPacket::parse(&packet);
    }

    #[test]
    fn parse_never_panics_on_corrupted_header(
        corrupted_bytes in prop::collection::vec(any::<u8>(), 240..600),
        corruption_indices in prop::collection::vec(0usize..240, 1..10),
        corruption_values in prop::collection::vec(any::<u8>(), 1..10)
    ) {
        let mut packet = corrupted_bytes;
        if packet.len() >= 240 {
            packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        }
        for (index, value) in corruption_indices.iter().zip(corruption_values.iter()) {
            if *index < packet.len() {
                packet[*index] = *value;
            }
        }
        let _ = DhcpPacket::parse(&packet);
    }

    #[test]
    fn parse_never_panics_on_random_option_lengths(
        option_code in 1u8..254,
        option_length in any::<u8>(),
        option_data in prop::collection::vec(any::<u8>(), 0..256)
    ) {
        let mut packet = valid_header();
        packet.push(option_code);
        packet.push(option_length);
        let actual_len = (option_length as usize).min(option_data.len());
        packet.extend_from_slice(&option_data[..actual_len]);
        packet.push(255);
        let _ = DhcpPacket::parse(&packet);
    }

    #[test]
    fn parse_never_panics_on_nested_overload(
        overload_flag in 1u8..=3,
        sname_data in prop::collection::vec(any::<u8>(), 64..=64),
        file_data in prop::collection::vec(any::<u8>(), 128..=128)
    ) {
        let mut packet = valid_header();
        packet[44..108].copy_from_slice(&sname_data);
        packet[108..236].copy_from_slice(&file_data);
        packet.push(52);
        packet.push(1);
        packet.push(overload_flag);
        packet.push(255);
        let _ = DhcpPacket::parse(&packet);
    }

    #[test]
    fn roundtrip_encode_decode_preserves_data(
        xid in any::<u32>(),
        secs in any::<u16>(),
        flags in any::<u16>(),
        ciaddr in any::<[u8; 4]>(),
        yiaddr in any::<[u8; 4]>(),
        siaddr in any::<[u8; 4]>(),
        giaddr in any::<[u8; 4]>(),
        chaddr in any::<[u8; 16]>(),
    ) {
        let mut packet = valid_header();
        packet[4..8].copy_from_slice(&xid.to_be_bytes());
        packet[8..10].copy_from_slice(&secs.to_be_bytes());
        packet[10..12].copy_from_slice(&flags.to_be_bytes());
        packet[12..16].copy_from_slice(&ciaddr);
        packet[16..20].copy_from_slice(&yiaddr);
        packet[20..24].copy_from_slice(&siaddr);
        packet[24..28].copy_from_slice(&giaddr);
        packet[28..44].copy_from_slice(&chaddr);
        packet.push(255);

        if let Ok(parsed) = DhcpPacket::parse(&packet) {
            let encoded = parsed.encode();
            let reparsed = DhcpPacket::parse(&encoded).unwrap();

            prop_assert_eq!(parsed.xid, reparsed.xid);
            prop_assert_eq!(parsed.secs, reparsed.secs);
            prop_assert_eq!(parsed.flags, reparsed.flags);
            prop_assert_eq!(parsed.ciaddr, reparsed.ciaddr);
            prop_assert_eq!(parsed.yiaddr, reparsed.yiaddr);
            prop_assert_eq!(parsed.siaddr, reparsed.siaddr);
            prop_assert_eq!(parsed.giaddr, reparsed.giaddr);
            prop_assert_eq!(parsed.chaddr, reparsed.chaddr);
        }
    }

    #[test]
    fn valid_packets_always_encode_to_at_least_300_bytes(
        xid in any::<u32>()
    ) {
        let mut packet = valid_header();
        packet[4..8].copy_from_slice(&xid.to_be_bytes());
        packet.push(255);

        if let Ok(parsed) = DhcpPacket::parse(&packet) {
            let encoded = parsed.encode();
            prop_assert!(encoded.len() >= 300);
        }
    }

    #[test]
    fn short_packets_always_rejected(
        data in prop::collection::vec(any::<u8>(), 0..240)
    ) {
        let result = DhcpPacket::parse(&data);
        prop_assert!(result.is_err());
    }

    #[test]
    fn bad_magic_cookie_always_rejected(
        cookie in any::<[u8; 4]>()
    ) {
        prop_assume!(cookie != DHCP_MAGIC_COOKIE);

        let mut packet = valid_header();
        packet[236..240].copy_from_slice(&cookie);
        packet.push(255);

        let result = DhcpPacket::parse(&packet);
        prop_assert!(result.is_err());
    }

    #[test]
    fn excessive_hops_always_rejected(
        hops in 17u8..=255
    ) {
        let mut packet = valid_header();
        packet[3] = hops;
        packet.push(255);

        let result = DhcpPacket::parse(&packet);
        prop_assert!(result.is_err());
    }
}
