#!/bin/bash
# NG Setup test battery against Ella Core via 3gpp-server-tester
# Run inside the 3gpp-server-tester container

TESTER="http://localhost:8080"
PASS=0
FAIL=0
TESTS=()

test_case() {
    local name="$1"
    local data="$2"
    local expect_status="$3"  # "success" or "failure" or http status code
    local expect_contains="$4" # optional string to check in response

    echo "---"
    echo "TEST: $name"

    resp=$(curl -s -w "\n%{http_code}" -X POST "$TESTER/gnb" -H 'Content-Type: application/json' -d "$data")
    http_code=$(echo "$resp" | tail -1)
    body=$(echo "$resp" | sed '$d')

    echo "  HTTP: $http_code"
    echo "  Response: $(echo "$body" | head -c 300)"

    passed=true

    if [ "$expect_status" = "success" ]; then
        if [ "$http_code" != "201" ]; then
            echo "  FAIL: Expected 201, got $http_code"
            passed=false
        fi
        if ! echo "$body" | grep -q "NGSetupResponse"; then
            echo "  FAIL: Expected NGSetupResponse in body"
            passed=false
        fi
    elif [ "$expect_status" = "failure" ]; then
        if echo "$body" | grep -q "NGSetupResponse"; then
            # Got a success when we expected failure
            echo "  FAIL: Expected failure but got NGSetupResponse"
            passed=false
        fi
    elif [ "$expect_status" = "setup_failure" ]; then
        if ! echo "$body" | grep -q "NGSetupFailure"; then
            echo "  FAIL: Expected NGSetupFailure in body"
            passed=false
        fi
    else
        if [ "$http_code" != "$expect_status" ]; then
            echo "  FAIL: Expected HTTP $expect_status, got $http_code"
            passed=false
        fi
    fi

    if [ -n "$expect_contains" ]; then
        if ! echo "$body" | grep -q "$expect_contains"; then
            echo "  FAIL: Expected body to contain: $expect_contains"
            passed=false
        fi
    fi

    if $passed; then
        echo "  PASS"
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
    fi

    # Clean up: delete the gnb if it was created
    if [ "$http_code" = "201" ]; then
        gnb_id=$(echo "$body" | grep -o '"gnb_id":"[^"]*"' | head -1 | cut -d'"' -f4)
        if [ -n "$gnb_id" ]; then
            curl -s -X DELETE "$TESTER/gnb/$gnb_id" > /dev/null
            sleep 0.2
        fi
    fi
}

echo "========================================="
echo "NG Setup Test Battery"
echo "========================================="

# --- HAPPY PATH TESTS ---

test_case "1. Basic NGSetup - MCC=001, MNC=01, SST=1" \
    '{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"01","tac":"000001","gnb_id":"000001","name":"test-gnb-1","sst":1}' \
    "success"

test_case "2. Different gNB ID" \
    '{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"01","tac":"000001","gnb_id":"000099","name":"test-gnb-99","sst":1}' \
    "success"

test_case "3. 3-digit MNC (001/001)" \
    '{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"001","tac":"000001","gnb_id":"000002","name":"test-gnb-3digit","sst":1}' \
    "success"

test_case "4. With SD value" \
    '{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"01","tac":"000001","gnb_id":"000003","name":"test-gnb-sd","sst":1,"sd":"000001"}' \
    "success"

test_case "5. Long gNB name" \
    '{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"01","tac":"000001","gnb_id":"000004","name":"this-is-a-very-long-gnb-name-for-testing-purposes","sst":1}' \
    "success"

test_case "6. TAC=000002 (different tracking area)" \
    '{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"01","tac":"000002","gnb_id":"000005","name":"test-gnb-tac2","sst":1}' \
    "success"

# --- WRONG PLMN TESTS ---
# Ella Core is configured for MCC=001, MNC=01. Other PLMNs should be rejected.

test_case "7. Wrong MCC (999/01) - should get NGSetupFailure" \
    '{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"999","mnc":"01","tac":"000001","gnb_id":"000006","name":"test-gnb-wrongmcc","sst":1}' \
    "setup_failure" \
    "cause"

test_case "8. Wrong MNC (001/99) - should get NGSetupFailure" \
    '{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"99","tac":"000001","gnb_id":"000007","name":"test-gnb-wrongmnc","sst":1}' \
    "setup_failure" \
    "cause"

test_case "9. Completely wrong PLMN (310/410)" \
    '{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"310","mnc":"410","tac":"000001","gnb_id":"000008","name":"test-gnb-us-plmn","sst":1}' \
    "setup_failure" \
    "cause"

# --- WRONG SLICE TESTS ---

test_case "10. Wrong SST (2 instead of 1)" \
    '{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"01","tac":"000001","gnb_id":"000009","name":"test-gnb-wrongsst","sst":2}' \
    "setup_failure" \
    "cause"

test_case "11. SST=0 (invalid)" \
    '{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"01","tac":"000001","gnb_id":"00000a","name":"test-gnb-sst0","sst":0}' \
    "setup_failure"

# --- CUSTOM IE TESTS (using ng_setup_ies to control individual IEs) ---

test_case "12. Custom IEs - valid NGSetup via raw IE list" \
    '{
        "amf_address":"10.3.0.2:38412",
        "gnb_n2_address":"10.3.0.3",
        "ng_setup_ies": [
            {"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"00000b","gnb_id_bit_length":24}}},
            {"id":82,"criticality":"ignore","ran_node_name":"test-gnb-custom-ies"},
            {"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}]}},
            {"id":21,"criticality":"ignore","default_paging_drx":3}
        ]
    }' \
    "success"

test_case "13. Custom IEs - missing GlobalRANNodeID (mandatory IE omitted)" \
    '{
        "amf_address":"10.3.0.2:38412",
        "gnb_n2_address":"10.3.0.3",
        "ng_setup_ies": [
            {"id":82,"criticality":"ignore","ran_node_name":"test-gnb-no-ranid"},
            {"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}]}},
            {"id":21,"criticality":"ignore","default_paging_drx":3}
        ]
    }' \
    "failure"

test_case "14. Custom IEs - missing SupportedTAList (mandatory IE omitted)" \
    '{
        "amf_address":"10.3.0.2:38412",
        "gnb_n2_address":"10.3.0.3",
        "ng_setup_ies": [
            {"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"00000c","gnb_id_bit_length":24}}},
            {"id":82,"criticality":"ignore","ran_node_name":"test-gnb-no-ta"},
            {"id":21,"criticality":"ignore","default_paging_drx":3}
        ]
    }' \
    "failure"

test_case "15. Custom IEs - missing DefaultPagingDRX (mandatory IE omitted)" \
    '{
        "amf_address":"10.3.0.2:38412",
        "gnb_n2_address":"10.3.0.3",
        "ng_setup_ies": [
            {"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"00000d","gnb_id_bit_length":24}}},
            {"id":82,"criticality":"ignore","ran_node_name":"test-gnb-no-drx"},
            {"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}]}}
        ]
    }' \
    "failure"

test_case "16. Custom IEs - wrong criticality on GlobalRANNodeID (ignore instead of reject)" \
    '{
        "amf_address":"10.3.0.2:38412",
        "gnb_n2_address":"10.3.0.3",
        "ng_setup_ies": [
            {"id":27,"criticality":"ignore","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"00000e","gnb_id_bit_length":24}}},
            {"id":82,"criticality":"ignore","ran_node_name":"test-gnb-wrong-crit"},
            {"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}]}},
            {"id":21,"criticality":"ignore","default_paging_drx":3}
        ]
    }' \
    "success"

test_case "17. Custom IEs - IEs in wrong order (SupportedTAList before GlobalRANNodeID)" \
    '{
        "amf_address":"10.3.0.2:38412",
        "gnb_n2_address":"10.3.0.3",
        "ng_setup_ies": [
            {"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}]}},
            {"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"00000f","gnb_id_bit_length":24}}},
            {"id":82,"criticality":"ignore","ran_node_name":"test-gnb-wrong-order"},
            {"id":21,"criticality":"ignore","default_paging_drx":3}
        ]
    }' \
    "success"

test_case "18. Custom IEs - empty gNB name (omit RANNodeName)" \
    '{
        "amf_address":"10.3.0.2:38412",
        "gnb_n2_address":"10.3.0.3",
        "ng_setup_ies": [
            {"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"000010","gnb_id_bit_length":24}}},
            {"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}]}},
            {"id":21,"criticality":"ignore","default_paging_drx":3}
        ]
    }' \
    "success"

test_case "19. Custom IEs - multiple slices in SupportedTAList" \
    '{
        "amf_address":"10.3.0.2:38412",
        "gnb_n2_address":"10.3.0.3",
        "ng_setup_ies": [
            {"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"000011","gnb_id_bit_length":24}}},
            {"id":82,"criticality":"ignore","ran_node_name":"test-gnb-multi-slice"},
            {"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"},{"sst":"02"},{"sst":"03","sd":"000001"}]}]}]}},
            {"id":21,"criticality":"ignore","default_paging_drx":3}
        ]
    }' \
    "success"

test_case "20. Custom IEs - multiple TAIs" \
    '{
        "amf_address":"10.3.0.2:38412",
        "gnb_n2_address":"10.3.0.3",
        "ng_setup_ies": [
            {"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"000012","gnb_id_bit_length":24}}},
            {"id":82,"criticality":"ignore","ran_node_name":"test-gnb-multi-tai"},
            {"id":102,"criticality":"reject","supported_ta_list":{"items":[
                {"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]},
                {"tac":"000002","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}
            ]}},
            {"id":21,"criticality":"ignore","default_paging_drx":3}
        ]
    }' \
    "success"

test_case "21. Custom IEs - PLMN mismatch between GlobalRANNodeID and SupportedTAList" \
    '{
        "amf_address":"10.3.0.2:38412",
        "gnb_n2_address":"10.3.0.3",
        "ng_setup_ies": [
            {"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"000013","gnb_id_bit_length":24}}},
            {"id":82,"criticality":"ignore","ran_node_name":"test-gnb-plmn-mismatch"},
            {"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"09f919","slice_support":[{"sst":"01"}]}]}]}},
            {"id":21,"criticality":"ignore","default_paging_drx":3}
        ]
    }' \
    "setup_failure"

test_case "22. Custom IEs - empty SupportedTAList (no TA items)" \
    '{
        "amf_address":"10.3.0.2:38412",
        "gnb_n2_address":"10.3.0.3",
        "ng_setup_ies": [
            {"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"000014","gnb_id_bit_length":24}}},
            {"id":82,"criticality":"ignore","ran_node_name":"test-gnb-empty-ta"},
            {"id":102,"criticality":"reject","supported_ta_list":{"items":[]}},
            {"id":21,"criticality":"ignore","default_paging_drx":3}
        ]
    }' \
    "failure"

test_case "23. Custom IEs - PagingDRX value 0 (v32)" \
    '{
        "amf_address":"10.3.0.2:38412",
        "gnb_n2_address":"10.3.0.3",
        "ng_setup_ies": [
            {"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"000015","gnb_id_bit_length":24}}},
            {"id":82,"criticality":"ignore","ran_node_name":"test-gnb-drx-v32"},
            {"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}]}},
            {"id":21,"criticality":"ignore","default_paging_drx":0}
        ]
    }' \
    "success"

test_case "24. Custom IEs - multiple broadcast PLMNs for one TAI (one matching, one not)" \
    '{
        "amf_address":"10.3.0.2:38412",
        "gnb_n2_address":"10.3.0.3",
        "ng_setup_ies": [
            {"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"000016","gnb_id_bit_length":24}}},
            {"id":82,"criticality":"ignore","ran_node_name":"test-gnb-multi-bplmn"},
            {"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[
                {"plmn_identity":"00f110","slice_support":[{"sst":"01"}]},
                {"plmn_identity":"09f919","slice_support":[{"sst":"01"}]}
            ]}]}},
            {"id":21,"criticality":"ignore","default_paging_drx":3}
        ]
    }' \
    "success"

# --- CONNECTION ERROR TESTS ---

test_case "25. Wrong AMF address (connection refused)" \
    '{"amf_address":"10.3.0.2:12345","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"01","tac":"000001","gnb_id":"000017","name":"test-gnb-wrongport","sst":1}' \
    "502"

test_case "26. Unreachable AMF address" \
    '{"amf_address":"10.99.99.99:38412","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"01","tac":"000001","gnb_id":"000018","name":"test-gnb-unreachable","sst":1}' \
    "502"

echo ""
echo "========================================="
echo "RESULTS: $PASS passed, $FAIL failed out of $((PASS + FAIL)) tests"
echo "========================================="
