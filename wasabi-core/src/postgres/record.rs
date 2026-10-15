use sea_query::Value;

/// Column values by name, in the order they were given.
///
/// Used both as the data of an insert or update and as an equality filter. Setting a column a
/// second time replaces its value, so a record never names a column twice.
///
/// ```rust,ignore
/// let record = Record::new().with("id", "0815").with("logins", 3_i64);
/// let record = record! { "id" => "0815", "logins" => 3_i64 };
/// let record = Record::from([("id", "0815"), ("email", "a@example.com")]);
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Record {
    fields: Vec<(String, Value)>,
}

impl Record {
    /// An empty record.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the record with `column` set to `value`.
    pub fn with(mut self, column: impl Into<String>, value: impl Into<Value>) -> Self {
        let _ = self.set(column, value);
        self
    }

    /// Sets `column` to `value`, replacing an earlier value of the same column.
    pub fn set(&mut self, column: impl Into<String>, value: impl Into<Value>) -> &mut Self {
        let column = column.into();
        let value = value.into();
        match self.fields.iter_mut().find(|(name, _)| *name == column) {
            Some(field) => field.1 = value,
            None => self.fields.push((column, value)),
        }
        self
    }

    /// The value of `column`, if set.
    pub fn get(&self, column: &str) -> Option<&Value> {
        self.fields
            .iter()
            .find(|(name, _)| name == column)
            .map(|(_, value)| value)
    }

    /// The column names, in order.
    pub fn columns(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().map(|(name, _)| name.as_str())
    }

    /// The `(column, value)` pairs, in order.
    pub fn fields(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.fields
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }

    /// Whether no column is set.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// The number of columns set.
    pub fn len(&self) -> usize {
        self.fields.len()
    }
}

impl<C: Into<String>, V: Into<Value>, const N: usize> From<[(C, V); N]> for Record {
    fn from(fields: [(C, V); N]) -> Self {
        fields.into_iter().collect()
    }
}

impl<C: Into<String>, V: Into<Value>> FromIterator<(C, V)> for Record {
    fn from_iter<I: IntoIterator<Item = (C, V)>>(iter: I) -> Self {
        let mut record = Record::new();
        for (column, value) in iter {
            let _ = record.set(column, value);
        }
        record
    }
}

/// Builds a [`Record`] from `column => value` pairs of mixed value types.
///
/// ```rust,ignore
/// let record = record! { "id" => "0815", "logins" => 3_i64, "deleted" => None::<String> };
/// ```
#[macro_export]
macro_rules! record {
    ($($column:expr => $value:expr),* $(,)?) => {
        $crate::postgres::Record::new()$(.with($column, $value))*
    };
}

/// Whether `value` is SQL `NULL`. sea-query's nulls are typed, so this compares against the
/// value's own null.
pub(crate) fn is_null(value: &Value) -> bool {
    *value == value.as_null()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setting_a_column_twice_replaces_it() {
        let record = Record::new().with("a", 1).with("b", "x").with("a", 2);
        assert_eq!(record.len(), 2);
        assert_eq!(record.get("a"), Some(&Value::from(2)));
        assert_eq!(record.columns().collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn the_macro_takes_mixed_types() {
        let record = crate::record! { "id" => "0815", "n" => 3_i64, "gone" => None::<String> };
        assert_eq!(record.get("id"), Some(&Value::from("0815")));
        assert_eq!(record.get("n"), Some(&Value::from(3_i64)));
        assert!(record.get("gone").is_some_and(is_null));
        assert!(!record.get("id").is_some_and(is_null));
    }

    #[test]
    fn records_build_from_arrays() {
        let record = Record::from([("a", "1"), ("b", "2")]);
        assert_eq!(record.columns().collect::<Vec<_>>(), vec!["a", "b"]);
    }
}
