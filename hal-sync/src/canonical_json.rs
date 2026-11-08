use serde_json::{Map, Number, Value};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanonicalJsonError {
    #[error("floating-point values are not allowed in canonical JSON")]
    FloatNotAllowed,
    #[error("JSON serialization failed: {0}")]
    Serialize(String),
}

pub fn canonicalize_json(value: &Value) -> Result<String, CanonicalJsonError> {
    let mut output = String::new();
    write_value(value, &mut output)?;
    Ok(output)
}

pub fn canonical_bytes_of(value: &Value) -> Result<Vec<u8>, CanonicalJsonError> {
    Ok(canonicalize_json(value)?.into_bytes())
}

fn write_value(value: &Value, output: &mut String) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(number) => write_number(number, output)?,
        Value::String(value) => write_string(value, output)?,
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_value(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => write_object(values, output)?,
    }
    Ok(())
}

fn write_number(number: &Number, output: &mut String) -> Result<(), CanonicalJsonError> {
    if number.is_i64() || number.is_u64() {
        output.push_str(&number.to_string());
        Ok(())
    } else {
        Err(CanonicalJsonError::FloatNotAllowed)
    }
}

fn write_string(value: &str, output: &mut String) -> Result<(), CanonicalJsonError> {
    let encoded = serde_json::to_string(value)
        .map_err(|error| CanonicalJsonError::Serialize(error.to_string()))?;
    output.push_str(&encoded);
    Ok(())
}

fn write_object(
    values: &Map<String, Value>,
    output: &mut String,
) -> Result<(), CanonicalJsonError> {
    let mut entries: Vec<_> = values.iter().collect();
    entries.sort_unstable_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));

    output.push('{');
    for (index, (key, value)) in entries.into_iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write_string(key, output)?;
        output.push(':');
        write_value(value, output)?;
    }
    output.push('}');
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_sorts_object_keys() {
        let value = serde_json::json!({"b": 1, "a": 2});
        assert_eq!(
            canonicalize_json(&value).expect("canonicalize"),
            r#"{"a":2,"b":1}"#
        );
    }

    #[test]
    fn canonicalize_no_whitespace() {
        let value = serde_json::json!({"key": ["value", 3]});
        let canonical = canonicalize_json(&value).expect("canonicalize");
        assert_eq!(canonical, r#"{"key":["value",3]}"#);
    }

    #[test]
    fn canonicalize_nested_objects_sorted_recursively() {
        let value = serde_json::json!({"outer": {"z": 0, "a": 1}});
        assert_eq!(
            canonicalize_json(&value).expect("canonicalize"),
            r#"{"outer":{"a":1,"z":0}}"#
        );
    }

    #[test]
    fn canonicalize_rejects_float() {
        let value = serde_json::json!({"x": 1.5});
        assert_eq!(
            canonicalize_json(&value),
            Err(CanonicalJsonError::FloatNotAllowed)
        );
    }

    #[test]
    fn canonicalize_array_order_preserved() {
        let value = serde_json::json!([3, 1, 2]);
        assert_eq!(canonicalize_json(&value).expect("canonicalize"), "[3,1,2]");
    }
}
