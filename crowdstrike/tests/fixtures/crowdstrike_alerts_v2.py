QUERY_ALERTS_V2_SUCCESS_RESPONSE = {
    "status_code": 200,
    "body": {"errors": [], "resources": ["alert_id_1", "alert_id_2"]},
}
QUERY_ALERTS_V2_FAILURE_RESPONSE = {
    "status_code": 400,
    "body": {"errors": ["something went wrong?"], "resources": []},
}


def make_test_alert_data():
    expected_alert_1_id = "alert_id_1"
    expected_alert_1_hostname = "endpoint"
    expected_alert_1_process_name = "some.exe"
    expected_alert_1_parent_process_name = "parent.exe"
    expected_alert_1_grandparent_process_name = "grandparent.exe"
    expected_alert_1_display_name = "alert_displayname_1"
    expected_alert_1_created_timestamp = "2025-01-01T00:00:00Z"
    expected_alert_1_updated_timestamp = "2025-01-01T02:00:00Z"
    expected_alert_1_composite_id = "alert_id_1::composite_id_1"
    expected_alert_2_id = "alert_id_2"
    expected_alert_2_hostname = "endpoint"
    expected_alert_2_process_name = "other.exe"
    expected_alert_2_parent_process_name = "other_parent.exe"
    expected_alert_2_grandparent_process_name = "other_grandparent.exe"
    expected_alert_2_display_name = "alert_displayname_2"
    expected_alert_2_created_timestamp = "2025-01-01T01:00:00Z"
    expected_alert_2_updated_timestamp = "2025-01-01T03:00:00Z"
    expected_alert_2_composite_id = "alert_id_2::composite_id_2"
    expected_values = {
        expected_alert_1_id: {
            "hostname": expected_alert_1_hostname,
            "process_names": [
                expected_alert_1_process_name,
                expected_alert_1_parent_process_name,
                expected_alert_1_grandparent_process_name,
            ],
            "display_name": expected_alert_1_display_name,
            "created_timestamp": expected_alert_1_created_timestamp,
            "updated_timestamp": expected_alert_1_updated_timestamp,
            "composite_id": expected_alert_1_composite_id,
        },
        expected_alert_2_id: {
            "hostname": expected_alert_2_hostname,
            "process_names": [
                expected_alert_2_process_name,
                expected_alert_2_parent_process_name,
                expected_alert_2_grandparent_process_name,
            ],
            "display_name": expected_alert_2_display_name,
            "created_timestamp": expected_alert_2_created_timestamp,
            "updated_timestamp": expected_alert_2_updated_timestamp,
            "composite_id": expected_alert_2_composite_id,
        },
    }

    # note that this is a truncated structure matching only a subset of keys present
    # in a returned json from the crowdstrike API.
    # Here are only the keys that are relevant to our collector
    get_alerts_v2_success_response = {
        "status_code": 200,
        "body": {
            "resources": [
                {
                    "id": expected_alert_1_id,
                    "device": {"hostname": expected_alert_1_hostname},
                    "filename": expected_alert_1_process_name,
                    "parent_details": {
                        "filename": expected_alert_1_parent_process_name
                    },
                    "grandparent_details": {
                        "filename": expected_alert_1_grandparent_process_name
                    },
                    "pattern_disposition": 0,
                    "display_name": expected_alert_1_display_name,
                    "created_timestamp": expected_alert_1_created_timestamp,
                    "updated_timestamp": expected_alert_1_updated_timestamp,
                    "composite_id": expected_alert_1_composite_id,
                },
                {
                    "id": expected_alert_2_id,
                    "device": {"hostname": expected_alert_2_hostname},
                    "filename": expected_alert_2_process_name,
                    "parent_details": {
                        "filename": expected_alert_2_parent_process_name
                    },
                    "grandparent_details": {
                        "filename": expected_alert_2_grandparent_process_name
                    },
                    "pattern_disposition": 0,
                    "display_name": expected_alert_2_display_name,
                    "created_timestamp": expected_alert_2_created_timestamp,
                    "updated_timestamp": expected_alert_2_updated_timestamp,
                    "composite_id": expected_alert_2_composite_id,
                },
            ]
        },
    }
    get_alerts_v2_success_response_with_malformed_data = {
        "status_code": 200,
        "body": {
            "resources": [
                {},
            ]
        },
    }
    return (
        expected_values,
        get_alerts_v2_success_response,
        get_alerts_v2_success_response_with_malformed_data,
    )


(
    ALERT_DATA,
    GET_ALERTS_V2_SUCCESS_RESPONSE,
    GET_ALERTS_V2_SUCCESS_RESPONSE_WITH_MALFORMED_DATA,
) = make_test_alert_data()
GET_ALERTS_V2_SUCCESS_RESPONSE_NO_ITEMS = {
    "status_code": 200,
    "body": {"errors": [], "resources": []},
}
GET_ALERTS_V2_FAILURE_RESPONSE = {
    "status_code": 400,
    "body": {"errors": ["something wrong here"], "resources": []},
}
MOCKED_ALERT = {
    "composite_id": "composite_id",
    "created_timestamp": "2025-01-01T00:00:00Z",
    "updated_timestamp": "2025-01-01T02:00:00Z",
    "device": {
        "hostname": "endpoint",
    },
    "process_name": "some.exe",
    "display_name": "alert_displayname",
    "id": "alert_id",
    "filename": "some.exe",
    "parent_details": {
        "filename": "parent.exe",
    },
    "grandparent_details": {
        "filename": "grandparent.exe",
    },
    "pattern_disposition": 0,
}
