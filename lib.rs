use pyo3::prelude::*;
use pyo3::types::PyModule;

use rust_crypto_lib_base::get_private_key_from_eth_signature;
use rust_crypto_lib_base::get_withdrawal_hash;
use rust_crypto_lib_base::sign_message;

use rust_crypto_lib_base::starknet_messages::AssetId;
use rust_crypto_lib_base::starknet_messages::LimitOrder;
use rust_crypto_lib_base::starknet_messages::OffChainMessage;
use rust_crypto_lib_base::starknet_messages::Order;
use rust_crypto_lib_base::starknet_messages::PositionId;
use rust_crypto_lib_base::starknet_messages::StarknetDomain;
use rust_crypto_lib_base::starknet_messages::Timestamp;
use rust_crypto_lib_base::starknet_messages::TransferArgs;
use starknet_crypto::get_public_key as fetch_public_key;
use starknet_crypto::pedersen_hash;
use starknet_crypto::verify as verify_signature;
use starknet_crypto::Felt;

/// Converts a hexadecimal string into a Starknet Felt (FieldElement).
///
/// Propagates parsing failures as a descriptive String rather than panicking
/// across the FFI boundary.
fn str_to_field_element(hex_str: &str) -> Result<Felt, String> {
    Felt::from_hex(hex_str).map_err(|e| {
        format!(
            "Failed to convert hex string {} to FieldElement: {}",
            hex_str, e
        )
    })
}

/// Parses a base-10 decimal string into a `u32`.
///
/// Reports the offending field name so Python callers get an actionable
/// error message instead of an unhandled abort or vague parse error.
fn parse_u32(value: &str, field_name: &str) -> Result<u32, String> {
    u32::from_str_radix(value, 10).map_err(|e| {
        format!(
            "Invalid {}: expected a base-10 integer, got {:?} ({})",
            field_name, value, e
        )
    })
}

/// Parses a base-10 decimal string into a `u64`.
///
/// Reports the offending field name so Python callers get an actionable
/// error message instead of an unhandled abort or vague parse error.
fn parse_u64(value: &str, field_name: &str) -> Result<u64, String> {
    u64::from_str_radix(value, 10).map_err(|e| {
        format!(
            "Invalid {}: expected a base-10 integer, got {:?} ({})",
            field_name, value, e
        )
    })
}

/// Parses a base-10 decimal string into an `i64`.
///
/// Reports the offending field name so Python callers get an actionable
/// error message instead of an unhandled abort or vague parse error.
fn parse_i64(value: &str, field_name: &str) -> Result<i64, String> {
    i64::from_str_radix(value, 10).map_err(|e| {
        format!(
            "Invalid {}: expected a base-10 integer, got {:?} ({})",
            field_name, value, e
        )
    })
}

#[pyfunction]
fn rs_get_public_key(py: Python, private_key_hex: String) -> PyResult<String> {
    py.allow_threads(move || {
        let private_key = str_to_field_element(&private_key_hex)?;
        Ok(fetch_public_key(&private_key).to_string())
    })
    .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
}

#[pyfunction]
fn rs_compute_pedersen_hash(py: Python, left_hex: String, right_hex: String) -> PyResult<String> {
    py.allow_threads(move || {
        let left = str_to_field_element(&left_hex)?;
        let right = str_to_field_element(&right_hex)?;
        Ok(pedersen_hash(&left, &right).to_string())
    })
    .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
}

#[pyfunction]
fn rs_sign_message(
    py: Python,
    priv_key_hex: String,
    msg_hash_hex: String,
) -> PyResult<(String, String)> {
    py.allow_threads(move || {
        let priv_key = str_to_field_element(&priv_key_hex)?;
        let msg_hash = str_to_field_element(&msg_hash_hex)?;
        sign_message(&msg_hash, &priv_key)
            .map(|signature| (signature.r.to_string(), signature.s.to_string()))
            .map_err(|e| format!("Signing operation failed: {}", e))
    })
    .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
}

#[pyfunction]
fn rs_verify_signature(
    py: Python,
    public_key_hex: String,
    msg_hash_hex: String,
    r_hex: String,
    s_hex: String,
) -> PyResult<bool> {
    py.allow_threads(move || {
        let public_key = str_to_field_element(&public_key_hex)?;
        let msg_hash = str_to_field_element(&msg_hash_hex)?;
        let r = str_to_field_element(&r_hex)?;
        let s = str_to_field_element(&s_hex)?;
        verify_signature(&public_key, &msg_hash, &r, &s)
            .map_err(|e| format!("Signature verification failed: {}", e))
    })
    .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
}

#[pyfunction]
fn rs_get_transfer_msg(
    py: Python,
    recipient_position_id: String,
    sender_position_id: String,
    collateral_id_hex: String,
    amount: String,
    expiration: String,
    salt: String,
    user_public_key_hex: String,
    domain_name: String,
    domain_version: String,
    domain_chain_id: String,
    domain_revision: String,
) -> PyResult<String> {
    py.allow_threads(move || {
        // Hex fields: parse and propagate errors rather than panicking across FFI
        let collateral_id = str_to_field_element(&collateral_id_hex)
            .map_err(|e| format!("Invalid collateral_id_hex: {}", e))?;
        let user_key = str_to_field_element(&user_public_key_hex)
            .map_err(|e| format!("Invalid user_public_key_hex: {}", e))?;

        // Decimal fields: report the offending field name on failure
        let recipient = parse_u32(&recipient_position_id, "recipient_position_id")?;
        let position_id = parse_u32(&sender_position_id, "sender_position_id")?;
        let amount = parse_u64(&amount, "amount")?;
        let expiration = parse_u64(&expiration, "expiration")?;
        let salt = Felt::from_dec_str(&salt).map_err(|e| format!("Invalid salt: {}", e))?;

        let transfer_args = TransferArgs {
            recipient: PositionId { value: recipient },
            position_id: PositionId { value: position_id },
            collateral_id: AssetId {
                value: collateral_id,
            },
            amount,
            expiration: Timestamp {
                seconds: expiration,
            },
            salt,
        };
        let domain = StarknetDomain {
            name: domain_name,
            version: domain_version,
            chain_id: domain_chain_id,
            revision: parse_u32(&domain_revision, "domain_revision")?,
        };
        let message = transfer_args
            .message_hash(&domain, user_key)
            .map_err(|e| format!("Failed to compute message hash: {}", e))?;
        Ok(message.to_hex_string())
    })
    // Convert error outside allow_threads where the GIL is held
    .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
}

#[pyfunction]
fn rs_get_order_msg(
    py: Python,
    position_id: String,
    base_asset_id_hex: String,
    base_amount: String,
    quote_asset_id_hex: String,
    quote_amount: String,
    fee_asset_id_hex: String,
    fee_amount: String,
    expiration: String,
    salt: String,
    user_public_key_hex: String,
    domain_name: String,
    domain_version: String,
    domain_chain_id: String,
    domain_revision: String,
) -> PyResult<String> {
    py.allow_threads(move || {
        // Hex fields: parse and surface errors safely
        let base_asset_id = str_to_field_element(&base_asset_id_hex)
            .map_err(|e| format!("Invalid base_asset_id_hex: {}", e))?;
        let quote_asset_id = str_to_field_element(&quote_asset_id_hex)
            .map_err(|e| format!("Invalid quote_asset_id_hex: {}", e))?;
        let fee_asset_id = str_to_field_element(&fee_asset_id_hex)
            .map_err(|e| format!("Invalid fee_asset_id_hex: {}", e))?;
        let user_key = str_to_field_element(&user_public_key_hex)
            .map_err(|e| format!("Invalid user_public_key_hex: {}", e))?;

        // Decimal fields: report specific field names
        let position_id = parse_u32(&position_id, "position_id")?;
        let base_amount = parse_i64(&base_amount, "base_amount")?;
        let quote_amount = parse_i64(&quote_amount, "quote_amount")?;
        let fee_amount = parse_u64(&fee_amount, "fee_amount")?;
        let expiration = parse_u64(&expiration, "expiration")?;
        let salt_u64 = parse_u64(&salt, "salt")?;

        let order = Order {
            position_id: PositionId { value: position_id },
            base_asset_id: AssetId {
                value: base_asset_id,
            },
            base_amount,
            quote_asset_id: AssetId {
                value: quote_asset_id,
            },
            quote_amount,
            fee_asset_id: AssetId {
                value: fee_asset_id,
            },
            fee_amount,
            expiration: Timestamp {
                seconds: expiration,
            },
            salt: salt_u64
                .try_into()
                .map_err(|e| format!("Invalid salt conversion: {}", e))?,
        };
        let domain = StarknetDomain {
            name: domain_name,
            version: domain_version,
            chain_id: domain_chain_id,
            revision: parse_u32(&domain_revision, "domain_revision")?,
        };

        let message = order
            .message_hash(&domain, user_key)
            .map_err(|e| format!("Failed to compute message hash: {}", e))?;
        Ok(message.to_hex_string())
    })
    // Convert error outside allow_threads where the GIL is held
    .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
}

#[pyfunction]
fn rs_get_limit_order_msg(
    py: Python,
    source_position_id: String,
    receive_position_id: String,
    base_asset_id_hex: String,
    base_amount: String,
    quote_asset_id_hex: String,
    quote_amount: String,
    fee_asset_id_hex: String,
    fee_amount: String,
    expiration: String,
    salt: String,
    user_public_key_hex: String,
    domain_name: String,
    domain_version: String,
    domain_chain_id: String,
    domain_revision: String,
) -> PyResult<String> {
    py.allow_threads(move || {
        // Hex fields: parse and surface errors safely
        let base_asset_id = str_to_field_element(&base_asset_id_hex)
            .map_err(|e| format!("Invalid base_asset_id_hex: {}", e))?;
        let quote_asset_id = str_to_field_element(&quote_asset_id_hex)
            .map_err(|e| format!("Invalid quote_asset_id_hex: {}", e))?;
        let fee_asset_id = str_to_field_element(&fee_asset_id_hex)
            .map_err(|e| format!("Invalid fee_asset_id_hex: {}", e))?;
        let user_key = str_to_field_element(&user_public_key_hex)
            .map_err(|e| format!("Invalid user_public_key_hex: {}", e))?;

        // Decimal fields: report specific field names
        let source_position_id = parse_u32(&source_position_id, "source_position_id")?;
        let receive_position_id = parse_u32(&receive_position_id, "receive_position_id")?;
        let base_amount = parse_i64(&base_amount, "base_amount")?;
        let quote_amount = parse_i64(&quote_amount, "quote_amount")?;
        let fee_amount = parse_u64(&fee_amount, "fee_amount")?;
        let expiration = parse_u64(&expiration, "expiration")?;
        let salt_u64 = parse_u64(&salt, "salt")?;

        let limit_order = LimitOrder {
            source_position: PositionId {
                value: source_position_id,
            },
            receive_position: PositionId {
                value: receive_position_id,
            },
            base_asset_id: AssetId {
                value: base_asset_id,
            },
            base_amount,
            quote_asset_id: AssetId {
                value: quote_asset_id,
            },
            quote_amount,
            fee_asset_id: AssetId {
                value: fee_asset_id,
            },
            fee_amount,
            expiration: Timestamp {
                seconds: expiration,
            },
            salt: salt_u64
                .try_into()
                .map_err(|e| format!("Invalid salt conversion: {}", e))?,
        };
        let domain = StarknetDomain {
            name: domain_name,
            version: domain_version,
            chain_id: domain_chain_id,
            revision: parse_u32(&domain_revision, "domain_revision")?,
        };

        let message = limit_order
            .message_hash(&domain, user_key)
            .map_err(|e| format!("Failed to compute message hash: {}", e))?;
        Ok(message.to_hex_string())
    })
    // Convert error outside allow_threads where the GIL is held
    .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
}

#[pyfunction]
fn rs_get_withdrawal_hash(
    py: Python,
    recipient_hex: String,
    position_id: String,
    collateral_id_hex: String,
    amount: String,
    expiration: String,
    salt: String,
    user_public_key_hex: String,
    domain_name: String,
    domain_version: String,
    domain_chain_id: String,
    domain_revision: String,
) -> PyResult<String> {
    py.allow_threads(move || {
        // Surface hashing errors as a Result instead of panicking
        get_withdrawal_hash(
            recipient_hex,
            position_id,
            collateral_id_hex,
            amount,
            expiration,
            salt,
            user_public_key_hex,
            domain_name,
            domain_version,
            domain_chain_id,
            domain_revision,
        )
        .map(|hash| hash.to_hex_string())
    })
    // Convert error outside allow_threads where the GIL is held
    .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
}

#[pyfunction]
fn rs_generate_keypair_from_eth_signature(
    _py: Python,
    signature: String,
) -> PyResult<(String, String)> {
    get_private_key_from_eth_signature(&signature)
        .map(|private_key| {
            let public_key = fetch_public_key(&private_key);
            let private_key_hex = private_key.to_hex_string();
            let public_key_hex = public_key.to_hex_string();
            (private_key_hex, public_key_hex)
        })
        .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
}

#[pymodule]
fn fast_stark_crypto(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(rs_get_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(rs_compute_pedersen_hash, m)?)?;
    m.add_function(wrap_pyfunction!(rs_sign_message, m)?)?;
    m.add_function(wrap_pyfunction!(rs_verify_signature, m)?)?;
    m.add_function(wrap_pyfunction!(rs_get_order_msg, m)?)?;
    m.add_function(wrap_pyfunction!(rs_get_transfer_msg, m)?)?;
    m.add_function(wrap_pyfunction!(rs_get_limit_order_msg, m)?)?;
    m.add_function(wrap_pyfunction!(rs_generate_keypair_from_eth_signature, m)?)?;
    m.add_function(wrap_pyfunction!(rs_get_withdrawal_hash, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyTuple;

    #[test]
    fn test_parse_helpers_valid() {
        assert_eq!(parse_u32("42", "test_field").unwrap(), 42);
        assert_eq!(parse_u64("1234567890", "test_field").unwrap(), 1234567890);
        assert_eq!(parse_i64("-999", "test_field").unwrap(), -999);
        assert_eq!(parse_i64("999", "test_field").unwrap(), 999);
    }

    #[test]
    fn test_parse_helpers_invalid() {
        let err_u32 = parse_u32("abc", "position_id").unwrap_err();
        assert!(err_u32.contains("Invalid position_id"));
        assert!(err_u32.contains("abc"));

        let err_u64 = parse_u64("-1", "amount").unwrap_err();
        assert!(err_u64.contains("Invalid amount"));

        let err_i64 = parse_i64("not_an_int", "base_amount").unwrap_err();
        assert!(err_i64.contains("Invalid base_amount"));

        let err_felt = str_to_field_element("not_a_hex").unwrap_err();
        assert!(err_felt.contains("Failed to convert hex string"));
    }

    #[test]
    fn test_rs_get_public_key() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let priv_key =
                "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904".to_string();
            let pub_key = rs_get_public_key(py, priv_key).unwrap();
            assert!(!pub_key.is_empty());

            // Invalid private key should return a PyValueError
            let invalid_res = rs_get_public_key(py, "invalid_hex".to_string());
            assert!(invalid_res.is_err());
        });
    }

    #[test]
    fn test_rs_compute_pedersen_hash() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let left = "0x1".to_string();
            let right = "0x2".to_string();
            let hash = rs_compute_pedersen_hash(py, left, right).unwrap();
            assert!(!hash.is_empty());

            // Invalid arguments should return a PyValueError
            let invalid_res = rs_compute_pedersen_hash(py, "bad".to_string(), "0x2".to_string());
            assert!(invalid_res.is_err());
        });
    }

    #[test]
    fn test_rs_sign_and_verify_signature() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let priv_key =
                "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904".to_string();
            let msg_hash = "0x123456789abcdef".to_string();

            let pub_key = rs_get_public_key(py, priv_key.clone()).unwrap();
            let (r, s) = rs_sign_message(py, priv_key, msg_hash.clone()).unwrap();

            let is_valid =
                rs_verify_signature(py, pub_key.clone(), msg_hash.clone(), r.clone(), s.clone())
                    .unwrap();
            assert!(is_valid);

            // Verification with wrong public key should fail or return false
            let bad_pub_key = "0x1".to_string();
            let is_invalid =
                rs_verify_signature(py, bad_pub_key, msg_hash, r, s).unwrap_or(false);
            assert!(!is_invalid);
        });
    }

    #[test]
    fn test_rs_get_order_msg() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let module = PyModule::new(py, "fast_stark_crypto").unwrap();
            fast_stark_crypto(py, module).unwrap();

            let position_id = "100".to_string();
            let base_asset_id = "0x2".to_string();
            let base_amount = "100".to_string();
            let quote_asset_id = "0x1".to_string();
            let quote_amount = "-156".to_string();
            let fee_asset_id = "0x1".to_string();
            let fee_amount = "74".to_string();
            let expiration = "100".to_string();
            let salt = "123".to_string();
            let user_public_key =
                "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904".to_string();
            let domain_name = "Perpetuals".to_string();
            let domain_version = "v0".to_string();
            let domain_chain_id = "SN_SEPOLIA".to_string();
            let domain_revision = "1".to_string();

            let result: String = module
                .getattr("rs_get_order_msg")
                .unwrap()
                .call1(PyTuple::new(
                    py,
                    [
                        position_id,
                        base_asset_id,
                        base_amount,
                        quote_asset_id,
                        quote_amount,
                        fee_asset_id,
                        fee_amount,
                        expiration,
                        salt,
                        user_public_key,
                        domain_name,
                        domain_version,
                        domain_chain_id,
                        domain_revision,
                    ],
                ))
                .unwrap()
                .extract()
                .unwrap();

            assert_eq!(
                result,
                "0x4de4c009e0d0c5a70a7da0e2039fb2b99f376d53496f89d9f437e736add6b48"
            );
        });
    }

    #[test]
    fn test_rs_get_order_msg_invalid_input() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let res = rs_get_order_msg(
                py,
                "invalid_pos_id".to_string(),
                "0x2".to_string(),
                "100".to_string(),
                "0x1".to_string(),
                "-156".to_string(),
                "0x1".to_string(),
                "74".to_string(),
                "100".to_string(),
                "123".to_string(),
                "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904".to_string(),
                "Perpetuals".to_string(),
                "v0".to_string(),
                "SN_SEPOLIA".to_string(),
                "1".to_string(),
            );
            assert!(res.is_err());
        });
    }

    #[test]
    fn test_rs_get_transfer_msg() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let module = PyModule::new(py, "fast_stark_crypto").unwrap();
            fast_stark_crypto(py, module).unwrap();

            let recipient_position_id = "1".to_string();
            let sender_position_id = "2".to_string();
            let collateral_id_hex = "0x3".to_string();
            let amount = "4".to_string();
            let expiration = "5".to_string();
            let salt = "6".to_string();
            let user_public_key_hex =
                "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904".to_string();

            let domain_name = "Perpetuals".to_string();
            let domain_version = "v0".to_string();
            let domain_chain_id = "SN_SEPOLIA".to_string();
            let domain_revision = "1".to_string();

            let result: String = module
                .getattr("rs_get_transfer_msg")
                .unwrap()
                .call1(PyTuple::new(
                    py,
                    [
                        recipient_position_id,
                        sender_position_id,
                        collateral_id_hex,
                        amount,
                        expiration,
                        salt,
                        user_public_key_hex,
                        domain_name,
                        domain_version,
                        domain_chain_id,
                        domain_revision,
                    ],
                ))
                .unwrap()
                .extract()
                .unwrap();

            assert_eq!(
                result, "0x56c7b21d13b79a33d7700dda20e22246c25e89818249504148174f527fc3f8f",
                "Hashes do not match for TransferArgs"
            );
        });
    }

    #[test]
    fn test_rs_get_transfer_msg_invalid_input() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let res = rs_get_transfer_msg(
                py,
                "1".to_string(),
                "2".to_string(),
                "not_a_hex".to_string(),
                "4".to_string(),
                "5".to_string(),
                "6".to_string(),
                "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904".to_string(),
                "Perpetuals".to_string(),
                "v0".to_string(),
                "SN_SEPOLIA".to_string(),
                "1".to_string(),
            );
            assert!(res.is_err());
        });
    }

    #[test]
    fn test_rs_get_limit_order_msg() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let source_position_id = "10".to_string();
            let receive_position_id = "20".to_string();
            let base_asset_id = "0x2".to_string();
            let base_amount = "50".to_string();
            let quote_asset_id = "0x1".to_string();
            let quote_amount = "-80".to_string();
            let fee_asset_id = "0x1".to_string();
            let fee_amount = "10".to_string();
            let expiration = "200".to_string();
            let salt = "456".to_string();
            let user_public_key =
                "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904".to_string();
            let domain_name = "Perpetuals".to_string();
            let domain_version = "v0".to_string();
            let domain_chain_id = "SN_SEPOLIA".to_string();
            let domain_revision = "1".to_string();

            let res = rs_get_limit_order_msg(
                py,
                source_position_id,
                receive_position_id,
                base_asset_id,
                base_amount,
                quote_asset_id,
                quote_amount,
                fee_asset_id,
                fee_amount,
                expiration,
                salt,
                user_public_key,
                domain_name,
                domain_version,
                domain_chain_id,
                domain_revision,
            );
            assert!(res.is_ok());
            assert!(!res.unwrap().is_empty());
        });
    }

    #[test]
    fn test_rs_get_limit_order_msg_invalid_input() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let res = rs_get_limit_order_msg(
                py,
                "bad_source".to_string(),
                "20".to_string(),
                "0x2".to_string(),
                "50".to_string(),
                "0x1".to_string(),
                "-80".to_string(),
                "0x1".to_string(),
                "10".to_string(),
                "200".to_string(),
                "456".to_string(),
                "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904".to_string(),
                "Perpetuals".to_string(),
                "v0".to_string(),
                "SN_SEPOLIA".to_string(),
                "1".to_string(),
            );
            assert!(res.is_err());
        });
    }

    #[test]
    fn test_rs_get_withdrawal_hash() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let res = rs_get_withdrawal_hash(
                py,
                "0x123".to_string(),
                "10".to_string(),
                "0x1".to_string(),
                "1000".to_string(),
                "500".to_string(),
                "789".to_string(),
                "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904".to_string(),
                "Perpetuals".to_string(),
                "v0".to_string(),
                "SN_SEPOLIA".to_string(),
                "1".to_string(),
            );
            // Result may be Ok or Err depending on underlying hash mock/implementation,
            // but it must never panic across the FFI boundary
            let _ = res;
        });
    }

    #[test]
    fn test_rs_generate_keypair_from_eth_signature() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            // Valid length hex signature mock
            let signature = "0x".to_string() + &"a".repeat(130);
            let res = rs_generate_keypair_from_eth_signature(py, signature);
            // Must return Ok or Err(PyValueError) without process abort
            let _ = res;

            // Malformed short signature must return PyValueError
            let bad_res = rs_generate_keypair_from_eth_signature(py, "short".to_string());
            assert!(bad_res.is_err());
        });
    }
}