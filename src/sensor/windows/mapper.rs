//! Windows ETW compatibility mapping.
//!
//! Keeps the ETW-to-Sysmon compatibility layer on the Windows side of the
//! sensor boundary so shared normalization stays platform-agnostic.

use ferrisetw::EventRecord;

use crate::models::EventCategory;
use crate::sensor::{SensorAction, SensorNormalization};

pub fn normalization_for_record(
    category: EventCategory,
    action: SensorAction,
    record: &EventRecord,
) -> SensorNormalization {
    let action_code = action_code_for_record(category, action, record);
    let raw_event_id = raw_event_id_for_record(category, action_code, record);

    SensorNormalization {
        event_id: map_to_sysmon_id(category, action_code, raw_event_id),
        action_code,
    }
}

fn action_code_for_record(
    category: EventCategory,
    action: SensorAction,
    record: &EventRecord,
) -> u8 {
    match category {
        EventCategory::Process | EventCategory::ImageLoad => record.opcode(),
        EventCategory::Network => match record.event_id() {
            12 => 12,
            13 => 13,
            14 => 14,
            id if id >= 15 => 15,
            _ => match action {
                SensorAction::Disconnect => 13,
                SensorAction::Accept => 14,
                SensorAction::Connect => 12,
                _ => 0,
            },
        },
        EventCategory::File => match record.opcode() {
            64 | 65 | 70 | 71 | 72 => record.opcode(),
            _ => match action {
                SensorAction::Create => 64,
                SensorAction::Delete => 70,
                SensorAction::Rename => 71,
                SensorAction::Modify => 65,
                _ => 0,
            },
        },
        EventCategory::Registry => match record.opcode() {
            36 | 38 | 39 | 41 => record.opcode(),
            _ => match action {
                SensorAction::Create => 36,
                SensorAction::Delete => 38,
                SensorAction::Set => 39,
                _ => 0,
            },
        },
        EventCategory::Dns => 0,
        EventCategory::Scripting => 0,
        EventCategory::Wmi => 0,
        EventCategory::Service => 0,
        EventCategory::Task => 0,
    }
}

fn raw_event_id_for_record(category: EventCategory, action_code: u8, record: &EventRecord) -> u16 {
    match category {
        EventCategory::Process | EventCategory::ImageLoad => record.event_id(),
        EventCategory::Network => record.event_id(),
        EventCategory::File => u16::from(action_code),
        EventCategory::Registry => u16::from(action_code),
        EventCategory::Dns => record.event_id(),
        EventCategory::Scripting => record.event_id(),
        EventCategory::Wmi => record.event_id(),
        EventCategory::Service => 7045,
        EventCategory::Task => 106,
    }
}

/// Maps Windows ETW opcodes/event IDs to the existing Sysmon-compatible IDs.
fn map_to_sysmon_id(category: EventCategory, action_code: u8, raw_event_id: u16) -> u16 {
    match category {
        EventCategory::Process => match action_code {
            1 => 1,
            2 => 5,
            10 => 7,
            _ => raw_event_id,
        },
        EventCategory::ImageLoad => match action_code {
            10 => 7,
            _ => raw_event_id,
        },
        EventCategory::File => match action_code {
            64 | 65 => 11,
            70 | 72 => 23,
            _ => raw_event_id,
        },
        EventCategory::Registry => match action_code {
            36 | 38 | 41 => 12,
            39 => 13,
            _ => raw_event_id,
        },
        EventCategory::Network => match action_code {
            12 | 15 => 3,
            _ => raw_event_id,
        },
        EventCategory::Dns => 22,
        EventCategory::Wmi => 19,
        EventCategory::Scripting => 4104,
        EventCategory::Service => 7045,
        EventCategory::Task => 106,
    }
}

#[cfg(test)]
mod tests {
    use super::map_to_sysmon_id;
    use crate::models::EventCategory;

    #[test]
    fn process_start_maps_to_sysmon_1() {
        assert_eq!(map_to_sysmon_id(EventCategory::Process, 1, 999), 1);
    }

    #[test]
    fn file_create_maps_to_sysmon_11() {
        assert_eq!(map_to_sysmon_id(EventCategory::File, 64, 999), 11);
    }

    #[test]
    fn registry_setvalue_maps_to_sysmon_13() {
        assert_eq!(map_to_sysmon_id(EventCategory::Registry, 39, 999), 13);
    }

    #[test]
    fn network_udp_connect_maps_to_sysmon_3() {
        assert_eq!(map_to_sysmon_id(EventCategory::Network, 15, 999), 3);
    }
}
