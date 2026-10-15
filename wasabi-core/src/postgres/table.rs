use crate::postgres::error::{Error, Result};
use crate::postgres::record::{Record, is_null};
use crate::postgres::{GenericClient, Row, execute, fetch};
use sea_query::{Alias, Expr, ExprTrait, OnConflict, Query, SimpleExpr};

/// The column types a [`Table`] can declare.
///
/// Deliberately the handful a service needs; anything more exotic is a job for plain SQL. A
/// [`Record`] binds Rust values strictly by type: `i64` for `BigInt`, `i32` for `Integer`,
/// [`crate::postgres::Decimal`] for `Decimal` and `Numeric`,
/// `chrono::DateTime<Utc>` for `TimestampTz`, `serde_json::Value` for `Jsonb`, `Vec<u8>` for
/// `Bytea`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ColumnType {
    /// `TEXT`
    Text,
    /// `VARCHAR(n)`
    Varchar(u32),
    /// `BOOLEAN`
    Boolean,
    /// `SMALLINT`
    SmallInt,
    /// `INTEGER`
    Integer,
    /// `BIGINT`
    BigInt,
    /// `REAL`
    Real,
    /// `DOUBLE PRECISION` — never for money: use [`ColumnType::Decimal`].
    Double,
    /// `NUMERIC(precision, scale)`: exact, `precision` digits in total, `scale` of them after the
    /// point — `Decimal(12, 2)` holds up to 9 999 999 999.99. Postgres rounds a value with more
    /// fractional digits to `scale` and rejects one with too many integer digits.
    Decimal(u32, u32),
    /// `NUMERIC` without limits: exact, any magnitude, every fractional digit kept.
    Numeric,
    /// `TIMESTAMPTZ`
    TimestampTz,
    /// `TIMESTAMP` (without time zone)
    Timestamp,
    /// `DATE`
    Date,
    /// `BYTEA`
    Bytea,
    /// `JSON`
    Json,
    /// `JSONB`
    Jsonb,
}

impl ColumnType {
    /// The type as written in DDL, and as the schema diff compares it.
    pub fn sql(&self) -> String {
        match self {
            ColumnType::Text => "TEXT".to_owned(),
            ColumnType::Varchar(length) => format!("VARCHAR({length})"),
            ColumnType::Boolean => "BOOLEAN".to_owned(),
            ColumnType::SmallInt => "SMALLINT".to_owned(),
            ColumnType::Integer => "INTEGER".to_owned(),
            ColumnType::BigInt => "BIGINT".to_owned(),
            ColumnType::Real => "REAL".to_owned(),
            ColumnType::Double => "DOUBLE PRECISION".to_owned(),
            ColumnType::Decimal(precision, scale) => format!("NUMERIC({precision},{scale})"),
            ColumnType::Numeric => "NUMERIC".to_owned(),
            ColumnType::TimestampTz => "TIMESTAMPTZ".to_owned(),
            ColumnType::Timestamp => "TIMESTAMP".to_owned(),
            ColumnType::Date => "DATE".to_owned(),
            ColumnType::Bytea => "BYTEA".to_owned(),
            ColumnType::Json => "JSON".to_owned(),
            ColumnType::Jsonb => "JSONB".to_owned(),
        }
    }
}

/// A column of a [`Table`]. Nullable unless [`Column::not_null`] says otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    pub(crate) name: String,
    pub(crate) column_type: ColumnType,
    pub(crate) nullable: bool,
    pub(crate) default_sql: Option<String>,
}

impl Column {
    /// A nullable column without default.
    pub fn new(name: impl Into<String>, column_type: ColumnType) -> Self {
        Column {
            name: name.into(),
            column_type,
            nullable: true,
            default_sql: None,
        }
    }

    /// Makes the column `NOT NULL`.
    pub fn not_null(mut self) -> Self {
        self.nullable = false;
        self
    }

    /// Gives the column a default, as a raw SQL expression (`"0"`, `"now()"`, `"'{}'::jsonb"`).
    ///
    /// A `NOT NULL` column added to a table that already has rows needs one. Defaults are written
    /// on create and add, but not compared afterwards: Postgres reports them normalised
    /// (`'x'::text`), so comparing would flag changes that are none.
    pub fn default_sql(mut self, expression: impl Into<String>) -> Self {
        self.default_sql = Some(expression.into());
        self
    }

    /// The column's name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A secondary index of a [`Table`].
///
/// In the database it is named `{table}_{name}`, because index names are unique per schema, not
/// per table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Index {
    pub(crate) name: String,
    pub(crate) columns: Vec<String>,
    pub(crate) unique: bool,
}

impl Index {
    /// A non-unique index over `columns`, in order.
    pub fn new<I, C>(name: impl Into<String>, columns: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<String>,
    {
        Index {
            name: name.into(),
            columns: columns.into_iter().map(Into::into).collect(),
            unique: false,
        }
    }

    /// Makes the index `UNIQUE`.
    pub fn unique(mut self) -> Self {
        self.unique = true;
        self
    }
}

/// A table: its declared schema, and record-level access to its rows.
///
/// Every operation takes the client to run on — a pooled [`crate::postgres::Client`] or a
/// transaction — so several of them compose into one transaction. Column names in records are
/// checked against the declaration, so a typo fails before reaching the database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    pub(crate) name: String,
    pub(crate) columns: Vec<Column>,
    pub(crate) primary_key: Vec<String>,
    pub(crate) indices: Vec<Index>,
}

impl Table {
    /// A table with no columns yet.
    pub fn new(name: impl Into<String>) -> Self {
        Table {
            name: name.into(),
            columns: Vec::new(),
            primary_key: Vec::new(),
            indices: Vec::new(),
        }
    }

    /// Adds a column.
    pub fn column(mut self, column: Column) -> Self {
        self.columns.push(column);
        self
    }

    /// Declares the primary key. Its columns are `NOT NULL` whatever their declaration says.
    pub fn primary_key<I, C>(mut self, columns: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<String>,
    {
        self.primary_key = columns.into_iter().map(Into::into).collect();
        self
    }

    /// Adds a secondary index.
    pub fn index(mut self, index: Index) -> Self {
        self.indices.push(index);
        self
    }

    /// The table's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The declared columns.
    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    /// Whether `column` is part of the primary key.
    pub(crate) fn is_key(&self, column: &str) -> bool {
        self.primary_key.iter().any(|key| key == column)
    }

    /// The name of `index` in the database.
    pub(crate) fn index_name(&self, index: &Index) -> String {
        format!("{}_{}", self.name, index.name)
    }

    /// Inserts `record`. Fails with [`Error::UniqueViolation`] on a duplicate key.
    ///
    /// # Errors
    ///
    /// Fails on an unknown column, an empty record, or if the database rejects the row.
    pub async fn insert<C: GenericClient + Sync>(&self, client: &C, record: Record) -> Result<u64> {
        self.check(&record, "insert")?;
        let (columns, values) = split(record);
        let mut statement = Query::insert();
        let _ = statement
            .into_table(Alias::new(&self.name))
            .columns(columns)
            .values(values)
            .map_err(Error::other)?;
        execute(client, &statement).await
    }

    /// Inserts `record` unless it collides with an existing key or unique index. Returns whether
    /// a row was written.
    ///
    /// # Errors
    ///
    /// Fails on an unknown column, an empty record, or if the database rejects the row.
    pub async fn insert_if_absent<C: GenericClient + Sync>(
        &self,
        client: &C,
        record: Record,
    ) -> Result<bool> {
        self.check(&record, "insert")?;
        let (columns, values) = split(record);
        let mut statement = Query::insert();
        let _ = statement
            .into_table(Alias::new(&self.name))
            .columns(columns)
            .values(values)
            .map_err(Error::other)?
            .on_conflict(OnConflict::new().do_nothing().to_owned());
        Ok(execute(client, &statement).await? > 0)
    }

    /// Inserts `record`, or — if a row with the same primary key exists — overwrites that row's
    /// other columns given in `record`.
    ///
    /// # Errors
    ///
    /// Fails on an unknown column, an empty record, a table without primary key, a record that
    /// lacks a key column, or if the database rejects the row.
    pub async fn upsert<C: GenericClient + Sync>(&self, client: &C, record: Record) -> Result<u64> {
        self.check(&record, "upsert")?;
        if self.primary_key.is_empty() {
            return Err(Error::other(format!(
                "Cannot upsert into '{}': it has no primary key",
                self.name
            )));
        }
        if let Some(missing) = self
            .primary_key
            .iter()
            .find(|key| record.get(key).is_none())
        {
            return Err(Error::other(format!(
                "Cannot upsert into '{}': the record lacks key column '{missing}'",
                self.name
            )));
        }

        let updated = record
            .columns()
            .filter(|column| !self.is_key(column))
            .map(Alias::new)
            .collect::<Vec<_>>();
        let mut on_conflict = OnConflict::columns(self.primary_key.iter().map(Alias::new));
        let _ = if updated.is_empty() {
            on_conflict.do_nothing()
        } else {
            on_conflict.update_columns(updated)
        };

        let (columns, values) = split(record);
        let mut statement = Query::insert();
        let _ = statement
            .into_table(Alias::new(&self.name))
            .columns(columns)
            .values(values)
            .map_err(Error::other)?
            .on_conflict(on_conflict);
        execute(client, &statement).await
    }

    /// Sets the columns in `values` on every row matching `filter`. Returns the number of rows
    /// changed — `0` is how an optimistic-lock miss shows (`filter` naming the expected version).
    ///
    /// # Errors
    ///
    /// Fails on an unknown column, an empty `values`, an empty `filter` (an update of every row
    /// is never what a record API caller meant), or if the database rejects the statement.
    pub async fn update<C: GenericClient + Sync>(
        &self,
        client: &C,
        values: Record,
        filter: Record,
    ) -> Result<u64> {
        self.check(&values, "update")?;
        self.check(&filter, "filter an update by")?;
        let mut statement = Query::update();
        let _ = statement.table(Alias::new(&self.name)).values(
            values
                .fields()
                .map(|(column, value)| (Alias::new(column), SimpleExpr::from(value.clone()))),
        );
        for condition in conditions(&filter) {
            let _ = statement.and_where(condition);
        }
        execute(client, &statement).await
    }

    /// Deletes every row matching `filter`. Returns the number of rows deleted.
    ///
    /// # Errors
    ///
    /// Fails on an unknown column, an empty `filter`, or if the database rejects the statement.
    pub async fn delete<C: GenericClient + Sync>(&self, client: &C, filter: Record) -> Result<u64> {
        self.check(&filter, "filter a delete by")?;
        let mut statement = Query::delete();
        let _ = statement.from_table(Alias::new(&self.name));
        for condition in conditions(&filter) {
            let _ = statement.and_where(condition);
        }
        execute(client, &statement).await
    }

    /// All rows matching `filter`; an empty filter selects every row.
    ///
    /// # Errors
    ///
    /// Fails on an unknown column, or if the database rejects the query.
    pub async fn select<C: GenericClient + Sync>(
        &self,
        client: &C,
        filter: Record,
    ) -> Result<Vec<Row>> {
        self.check_columns(&filter)?;
        fetch(client, &self.select_statement(&filter)).await
    }

    /// The first row matching `filter`, if any. Meant for filters on a key; with several matches
    /// the one returned is arbitrary.
    ///
    /// # Errors
    ///
    /// Fails on an unknown column, or if the database rejects the query.
    pub async fn select_one<C: GenericClient + Sync>(
        &self,
        client: &C,
        filter: Record,
    ) -> Result<Option<Row>> {
        self.check_columns(&filter)?;
        let mut statement = self.select_statement(&filter);
        let _ = statement.limit(1);
        Ok(fetch(client, &statement).await?.into_iter().next())
    }

    /// A `SELECT *` over this table filtered by `filter`, to extend with ordering, limits or
    /// further conditions and run through [`crate::postgres::fetch`].
    pub fn select_statement(&self, filter: &Record) -> sea_query::SelectStatement {
        let mut statement = Query::select();
        let _ = statement
            .column(sea_query::Asterisk)
            .from(Alias::new(&self.name));
        for condition in conditions(filter) {
            let _ = statement.and_where(condition);
        }
        statement
    }

    /// Rejects an empty record, then unknown columns.
    fn check(&self, record: &Record, purpose: &str) -> Result<()> {
        if record.is_empty() {
            return Err(Error::other(format!(
                "Refusing to {purpose} an empty record in '{}'",
                self.name
            )));
        }
        self.check_columns(record)
    }

    /// Rejects columns the table does not declare.
    fn check_columns(&self, record: &Record) -> Result<()> {
        if let Some(unknown) = record
            .columns()
            .find(|column| !self.columns.iter().any(|known| known.name == *column))
        {
            return Err(Error::other(format!(
                "Table '{}' has no column '{unknown}'",
                self.name
            )));
        }
        Ok(())
    }
}

/// Splits a record into sea-query column identifiers and value expressions.
fn split(record: Record) -> (Vec<Alias>, Vec<SimpleExpr>) {
    record
        .fields()
        .map(|(column, value)| (Alias::new(column), SimpleExpr::from(value.clone())))
        .unzip()
}

/// `column = value` per field, `column IS NULL` for a null value.
fn conditions(filter: &Record) -> impl Iterator<Item = Expr> + '_ {
    filter.fields().map(|(column, value)| {
        if is_null(value) {
            Expr::col(Alias::new(column)).is_null()
        } else {
            Expr::col(Alias::new(column)).eq(value.clone())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::test::{database, unique_table};
    use crate::record;
    use sea_query::PostgresQueryBuilder;

    fn users(name: &str) -> Table {
        Table::new(name)
            .column(Column::new("id", ColumnType::Text))
            .column(Column::new("email", ColumnType::Text).not_null())
            .column(
                Column::new("logins", ColumnType::BigInt)
                    .not_null()
                    .default_sql("0"),
            )
            .column(Column::new("profile", ColumnType::Jsonb))
            .primary_key(["id"])
            .index(Index::new("by_email", ["email"]).unique())
    }

    #[test]
    fn filters_turn_null_into_is_null() {
        let table = users("users");
        let sql = table
            .select_statement(&record! { "id" => "a", "profile" => None::<serde_json::Value> })
            .to_string(PostgresQueryBuilder);
        assert_eq!(
            sql,
            r#"SELECT * FROM "users" WHERE "id" = 'a' AND "profile" IS NULL"#
        );
    }

    #[tokio::test]
    async fn decimals_round_trip_exactly() {
        use crate::postgres::Decimal;
        use std::str::FromStr;

        let Some(db) = database().await else { return };
        let table = Table::new(unique_table("decimals_round_trip"))
            .column(Column::new("id", ColumnType::Text))
            .column(Column::new("amount", ColumnType::Decimal(12, 2)).not_null())
            .column(Column::new("rate", ColumnType::Numeric))
            .primary_key(["id"]);
        let _ = db.ensure_exists(&table).await.unwrap();
        let client = db.client().await.unwrap();

        // 0.1 + 0.2 is the classic float trap; NUMERIC must give back exactly what went in.
        let amount = Decimal::from_str("0.1").unwrap() + Decimal::from_str("0.2").unwrap();
        let rate = Decimal::from_str("0.000000000123456789").unwrap();
        let _ = table
            .insert(
                &client,
                record! { "id" => "a", "amount" => amount, "rate" => rate },
            )
            .await
            .unwrap();
        let _ = table
            .insert(
                &client,
                record! { "id" => "b", "amount" => Decimal::from_str("9999999999.995").unwrap(), "rate" => None::<Decimal> },
            )
            .await
            .unwrap_err();
        let _ = table
            .insert(
                &client,
                record! { "id" => "c", "amount" => Decimal::from_str("1.005").unwrap(), "rate" => None::<Decimal> },
            )
            .await
            .unwrap();

        let a = table
            .select_one(&client, record! { "id" => "a" })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            a.get::<_, Decimal>("amount"),
            Decimal::from_str("0.30").unwrap()
        );
        assert_eq!(a.get::<_, Decimal>("rate"), rate);
        let c = table
            .select_one(&client, record! { "id" => "c" })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            c.get::<_, Decimal>("amount"),
            Decimal::from_str("1.01").unwrap(),
            "Postgres rounds to the declared scale, half away from zero"
        );
        assert_eq!(c.get::<_, Option<Decimal>>("rate"), None);

        let matched = table
            .select(
                &client,
                record! { "amount" => Decimal::from_str("0.3").unwrap() },
            )
            .await
            .unwrap();
        assert_eq!(matched.len(), 1, "0.3 and 0.30 are the same NUMERIC");

        client
            .batch_execute(&format!("DROP TABLE \"{}\"", table.name()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn records_are_checked_against_the_declaration() {
        let Some(db) = database().await else { return };
        let table = users(&unique_table("records_checked"));
        let client = db.client().await.unwrap();

        let unknown = table.insert(&client, record! { "nope" => 1 }).await;
        assert!(
            unknown
                .unwrap_err()
                .to_string()
                .contains("no column 'nope'")
        );
        let unfiltered = table
            .update(&client, record! { "logins" => 1_i64 }, Record::new())
            .await;
        assert!(unfiltered.unwrap_err().to_string().contains("empty record"));
        let unfiltered = table.delete(&client, Record::new()).await;
        assert!(unfiltered.unwrap_err().to_string().contains("empty record"));
    }

    #[tokio::test]
    async fn records_round_trip() {
        let Some(db) = database().await else { return };
        let table = users(&unique_table("records_round_trip"));
        let _ = db.ensure_exists(&table).await.unwrap();
        let client = db.client().await.unwrap();

        let profile = serde_json::json!({ "name": "Ada" });
        let inserted = table
            .insert(
                &client,
                record! { "id" => "1", "email" => "ada@example.com", "profile" => profile.clone() },
            )
            .await
            .unwrap();
        assert_eq!(inserted, 1);

        let duplicate = table
            .insert(
                &client,
                record! { "id" => "1", "email" => "other@example.com" },
            )
            .await
            .unwrap_err();
        assert!(duplicate.is_unique_violation(), "{duplicate:?}");
        assert_eq!(
            duplicate.constraint(),
            Some(format!("{}_pkey", table.name()).as_str())
        );
        // Still classifiable after `?` turned it into an anyhow::Error.
        let wrapped = anyhow::Error::from(duplicate).context("creating a user");
        assert!(
            crate::postgres::Error::find(&wrapped)
                .is_some_and(crate::postgres::Error::is_unique_violation)
        );
        assert!(
            !table
                .insert_if_absent(&client, record! { "id" => "1", "email" => "x@example.com" })
                .await
                .unwrap()
        );

        // Optimistic lock: the filter names the expected value, a miss changes nothing.
        let stale = table
            .update(
                &client,
                record! { "logins" => 2_i64 },
                record! { "id" => "1", "logins" => 5_i64 },
            )
            .await
            .unwrap();
        assert_eq!(stale, 0);
        let fresh = table
            .update(
                &client,
                record! { "logins" => 1_i64 },
                record! { "id" => "1", "logins" => 0_i64 },
            )
            .await
            .unwrap();
        assert_eq!(fresh, 1);

        let _ = table
            .upsert(
                &client,
                record! { "id" => "2", "email" => "bob@example.com" },
            )
            .await
            .unwrap();
        let _ = table
            .upsert(
                &client,
                record! { "id" => "2", "email" => "robert@example.com" },
            )
            .await
            .unwrap();

        let ada = table
            .select_one(&client, record! { "id" => "1" })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ada.get::<_, i64>("logins"), 1);
        assert_eq!(ada.get::<_, serde_json::Value>("profile"), profile);
        let bob = table
            .select_one(&client, record! { "id" => "2" })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bob.get::<_, String>("email"), "robert@example.com");
        let without_profile = table
            .select(&client, record! { "profile" => None::<serde_json::Value> })
            .await
            .unwrap();
        assert_eq!(without_profile.len(), 1);

        assert_eq!(
            table
                .delete(&client, record! { "id" => "2" })
                .await
                .unwrap(),
            1
        );
        assert_eq!(table.select(&client, Record::new()).await.unwrap().len(), 1);

        client
            .batch_execute(&format!("DROP TABLE \"{}\"", table.name()))
            .await
            .unwrap();
    }
}
