use crate::postgres::GenericClient;
use crate::postgres::table::{Column, ColumnType, Index, Table};
use anyhow::Context;

/// One step from the database as it is towards a [`Table`] declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaChange {
    /// What the change does, for a human: `"Table 'users' must be created"`.
    pub label: String,
    /// The statement(s) that make the change.
    pub sql: String,
    /// Whether running it may destroy data — a dropped column, a narrowed type.
    /// [`crate::postgres::Database::ensure_exists`] never runs these on its own.
    pub data_loss_expected: bool,
}

/// What [`crate::postgres::Database::ensure_exists`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SchemaSync {
    /// Changes that were applied.
    pub applied: Vec<SchemaChange>,
    /// Changes that may lose data and were left for an operator.
    pub withheld: Vec<SchemaChange>,
}

impl SchemaSync {
    /// Whether the table now matches its declaration.
    pub fn is_complete(&self) -> bool {
        self.withheld.is_empty()
    }
}

/// A table as the catalog reports it.
#[derive(Clone, Debug, Default)]
pub(crate) struct ExistingTable {
    pub(crate) columns: Vec<ExistingColumn>,
    /// Constraint name and columns.
    pub(crate) primary_key: Option<(String, Vec<String>)>,
    pub(crate) indices: Vec<ExistingIndex>,
}

#[derive(Clone, Debug)]
pub(crate) struct ExistingColumn {
    pub(crate) name: String,
    /// Normalised to [`ColumnType::sql`]'s spelling where the type is one of those.
    pub(crate) column_type: String,
    pub(crate) nullable: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ExistingIndex {
    pub(crate) name: String,
    pub(crate) columns: Vec<String>,
    pub(crate) unique: bool,
}

/// Reads `table` from the current schema; `None` if it does not exist.
pub(crate) async fn introspect<C: GenericClient + Sync>(
    client: &C,
    table: &str,
) -> anyhow::Result<Option<ExistingTable>> {
    let columns = client
        .query(
            "SELECT column_name::text, data_type::text, character_maximum_length, is_nullable::text,
                    numeric_precision, numeric_scale
             FROM information_schema.columns
             WHERE table_schema = current_schema() AND table_name = $1
             ORDER BY ordinal_position",
            &[&table],
        )
        .await
        .with_context(|| format!("Cannot read the columns of '{table}'"))?;
    if columns.is_empty() {
        return Ok(None);
    }

    let mut existing = ExistingTable::default();
    for row in columns {
        let data_type: String = row.try_get(1)?;
        let length: Option<i32> = row.try_get(2)?;
        let is_nullable: String = row.try_get(3)?;
        // For NUMERIC the catalog reports precision and scale; for the integer and float types
        // it reports them too (in bits, for floats), which `normalise_type` ignores.
        let precision: Option<i32> = row.try_get(4)?;
        let scale: Option<i32> = row.try_get(5)?;
        let column_type = match (data_type.as_str(), precision, scale) {
            ("numeric", Some(precision), Some(scale)) => format!("NUMERIC({precision},{scale})"),
            ("numeric", _, _) => "NUMERIC".to_owned(),
            _ => normalise_type(&data_type, length),
        };
        existing.columns.push(ExistingColumn {
            name: row.try_get(0)?,
            column_type,
            nullable: is_nullable == "YES",
        });
    }

    // Expression indices have attnum 0 and drop out of the join; they are none of ours.
    let indices = client
        .query(
            "SELECT i.relname::text, ix.indisunique, ix.indisprimary, c.conname::text,
                    array_agg(a.attname::text ORDER BY k.ord)
             FROM pg_class t
             JOIN pg_namespace n ON n.oid = t.relnamespace
             JOIN pg_index ix ON ix.indrelid = t.oid
             JOIN pg_class i ON i.oid = ix.indexrelid
             LEFT JOIN pg_constraint c ON c.conindid = ix.indexrelid AND c.contype = 'p'
             JOIN LATERAL unnest(ix.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord) ON true
             JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
             WHERE n.nspname = current_schema() AND t.relname = $1
             GROUP BY i.relname, ix.indisunique, ix.indisprimary, c.conname",
            &[&table],
        )
        .await
        .with_context(|| format!("Cannot read the indices of '{table}'"))?;
    for row in indices {
        let name: String = row.try_get(0)?;
        let unique: bool = row.try_get(1)?;
        let primary: bool = row.try_get(2)?;
        let constraint: Option<String> = row.try_get(3)?;
        let columns: Vec<String> = row.try_get(4)?;
        if primary {
            existing.primary_key = Some((constraint.unwrap_or(name), columns));
        } else {
            existing.indices.push(ExistingIndex {
                name,
                columns,
                unique,
            });
        }
    }

    Ok(Some(existing))
}

/// Maps `information_schema.columns.data_type` onto [`ColumnType::sql`]'s spelling, so declared
/// and existing types compare as strings. Types wasabi does not declare stay as Postgres names
/// them and simply never match.
fn normalise_type(data_type: &str, length: Option<i32>) -> String {
    match (data_type, length) {
        ("text", _) => "TEXT".to_owned(),
        ("character varying", Some(length)) => format!("VARCHAR({length})"),
        ("character varying", None) => "VARCHAR".to_owned(),
        ("boolean", _) => "BOOLEAN".to_owned(),
        ("smallint", _) => "SMALLINT".to_owned(),
        ("integer", _) => "INTEGER".to_owned(),
        ("bigint", _) => "BIGINT".to_owned(),
        ("real", _) => "REAL".to_owned(),
        ("double precision", _) => "DOUBLE PRECISION".to_owned(),
        ("timestamp with time zone", _) => "TIMESTAMPTZ".to_owned(),
        ("timestamp without time zone", _) => "TIMESTAMP".to_owned(),
        ("date", _) => "DATE".to_owned(),
        ("bytea", _) => "BYTEA".to_owned(),
        ("json", _) => "JSON".to_owned(),
        ("jsonb", _) => "JSONB".to_owned(),
        (other, _) => other.to_uppercase(),
    }
}

/// Everything it takes to turn `existing` into `table`, in an order that runs: indices that may
/// block a column change are dropped first, columns are dropped last.
pub(crate) fn diff(table: &Table, existing: Option<&ExistingTable>) -> Vec<SchemaChange> {
    let Some(existing) = existing else {
        return create(table);
    };

    let mut changes = Vec::new();
    let name = quote(&table.name);

    // Indices: only those named like ours (`{table}_…`) are managed; one an operator added by
    // hand under another name is left alone.
    let prefix = format!("{}_", table.name);
    for index in &existing.indices {
        let declared = table
            .indices
            .iter()
            .find(|declared| table.index_name(declared) == index.name);
        match declared {
            None if index.name.starts_with(&prefix) => changes.push(SchemaChange {
                label: format!("Index '{}' is no longer declared", index.name),
                sql: format!("DROP INDEX {}", quote(&index.name)),
                data_loss_expected: false,
            }),
            Some(declared)
                if declared.columns != index.columns || declared.unique != index.unique =>
            {
                changes.push(SchemaChange {
                    label: format!("Index '{}' must be rebuilt", index.name),
                    sql: format!(
                        "DROP INDEX {};\n{}",
                        quote(&index.name),
                        create_index(table, declared)
                    ),
                    data_loss_expected: false,
                });
            }
            _ => {}
        }
    }

    for column in &table.columns {
        let required = !column.nullable || table.is_key(&column.name);
        let Some(current) = existing.columns.iter().find(|c| c.name == column.name) else {
            let label = if required && column.default_sql.is_none() {
                format!(
                    "Column '{}' is missing (NOT NULL without default: fails if '{}' has rows)",
                    column.name, table.name
                )
            } else {
                format!("Column '{}' is missing", column.name)
            };
            changes.push(SchemaChange {
                label,
                sql: format!(
                    "ALTER TABLE {name} ADD COLUMN {}",
                    column_definition(table, column)
                ),
                data_loss_expected: false,
            });
            continue;
        };

        let wanted = column.column_type.sql();
        if current.column_type != wanted {
            changes.push(SchemaChange {
                label: format!(
                    "Column '{}' must change type from {} to {wanted}",
                    column.name, current.column_type
                ),
                sql: format!(
                    "ALTER TABLE {name} ALTER COLUMN {col} TYPE {wanted} USING {col}::{wanted}",
                    col = quote(&column.name)
                ),
                data_loss_expected: !is_widening(&current.column_type, &column.column_type),
            });
        }
        if required && current.nullable {
            changes.push(SchemaChange {
                label: format!(
                    "Column '{}' must become NOT NULL (fails while it holds NULLs)",
                    column.name
                ),
                sql: format!(
                    "ALTER TABLE {name} ALTER COLUMN {} SET NOT NULL",
                    quote(&column.name)
                ),
                data_loss_expected: false,
            });
        }
        if !required && !current.nullable {
            changes.push(SchemaChange {
                label: format!("Column '{}' must accept NULL", column.name),
                sql: format!(
                    "ALTER TABLE {name} ALTER COLUMN {} DROP NOT NULL",
                    quote(&column.name)
                ),
                data_loss_expected: false,
            });
        }
    }

    let current_key = existing.primary_key.as_ref();
    if current_key.map(|(_, columns)| columns) != Some(&table.primary_key)
        && !(current_key.is_none() && table.primary_key.is_empty())
    {
        let mut statements = Vec::new();
        if let Some((constraint, _)) = current_key {
            statements.push(format!(
                "ALTER TABLE {name} DROP CONSTRAINT {}",
                quote(constraint)
            ));
        }
        if !table.primary_key.is_empty() {
            statements.push(format!(
                "ALTER TABLE {name} ADD PRIMARY KEY ({})",
                quote_all(&table.primary_key)
            ));
        }
        changes.push(SchemaChange {
            label: format!("Primary key must be ({})", table.primary_key.join(", ")),
            sql: statements.join(";\n"),
            data_loss_expected: false,
        });
    }

    for index in &table.indices {
        let index_name = table.index_name(index);
        if !existing
            .indices
            .iter()
            .any(|current| current.name == index_name)
        {
            changes.push(SchemaChange {
                label: format!("Index '{index_name}' is missing"),
                sql: create_index(table, index),
                data_loss_expected: false,
            });
        }
    }

    for column in &existing.columns {
        if !table
            .columns
            .iter()
            .any(|declared| declared.name == column.name)
        {
            changes.push(SchemaChange {
                label: format!("Column '{}' is no longer declared", column.name),
                sql: format!("ALTER TABLE {name} DROP COLUMN {}", quote(&column.name)),
                data_loss_expected: true,
            });
        }
    }

    changes
}

/// The changes for a table that does not exist yet.
fn create(table: &Table) -> Vec<SchemaChange> {
    let mut definitions = table
        .columns
        .iter()
        .map(|column| column_definition(table, column))
        .collect::<Vec<_>>();
    if !table.primary_key.is_empty() {
        definitions.push(format!("PRIMARY KEY ({})", quote_all(&table.primary_key)));
    }

    let mut changes = vec![SchemaChange {
        label: format!("Table '{}' must be created", table.name),
        sql: format!(
            "CREATE TABLE {} (\n    {}\n)",
            quote(&table.name),
            definitions.join(",\n    ")
        ),
        data_loss_expected: false,
    }];
    for index in &table.indices {
        changes.push(SchemaChange {
            label: format!("Index '{}' must be created", table.index_name(index)),
            sql: create_index(table, index),
            data_loss_expected: false,
        });
    }
    changes
}

fn column_definition(table: &Table, column: &Column) -> String {
    let mut definition = format!("{} {}", quote(&column.name), column.column_type.sql());
    if !column.nullable || table.is_key(&column.name) {
        definition.push_str(" NOT NULL");
    }
    if let Some(default) = &column.default_sql {
        definition.push_str(" DEFAULT ");
        definition.push_str(default);
    }
    definition
}

fn create_index(table: &Table, index: &Index) -> String {
    format!(
        "CREATE {}INDEX {} ON {} ({})",
        if index.unique { "UNIQUE " } else { "" },
        quote(&table.index_name(index)),
        quote(&table.name),
        quote_all(&index.columns)
    )
}

/// Whether converting `from` to `to` keeps every value intact. Anything not known to be safe
/// counts as lossy — a false alarm costs an operator a look, a missed one costs data.
fn is_widening(from: &str, to: &ColumnType) -> bool {
    match to {
        // Every type has a text form, and casting to it never fails.
        ColumnType::Text => true,
        ColumnType::Varchar(length) => from
            .strip_prefix("VARCHAR(")
            .and_then(|rest| rest.strip_suffix(')'))
            .and_then(|current| current.parse::<u32>().ok())
            .is_some_and(|current| current <= *length),
        ColumnType::Integer => from == "SMALLINT",
        ColumnType::BigInt => from == "SMALLINT" || from == "INTEGER",
        ColumnType::Double => from == "REAL" || from == "SMALLINT" || from == "INTEGER",
        // Unbounded NUMERIC holds every integer and every NUMERIC exactly.
        ColumnType::Numeric => from.starts_with("NUMERIC") || integer_digits(from).is_some(),
        // Lossless when neither side of the point shrinks: no integer digit is cut off, no
        // fractional digit rounded away.
        ColumnType::Decimal(precision, scale) => {
            let integer_room = precision.saturating_sub(*scale);
            match decimal_shape(from) {
                Some((from_precision, from_scale)) => {
                    *scale >= from_scale
                        && integer_room >= from_precision.saturating_sub(from_scale)
                }
                None => integer_digits(from).is_some_and(|digits| integer_room >= digits),
            }
        }
        _ => false,
    }
}

/// `(precision, scale)` of a `NUMERIC(p,s)` type name.
fn decimal_shape(type_name: &str) -> Option<(u32, u32)> {
    let (precision, scale) = type_name
        .strip_prefix("NUMERIC(")?
        .strip_suffix(')')?
        .split_once(',')?;
    Some((precision.trim().parse().ok()?, scale.trim().parse().ok()?))
}

/// How many decimal digits the largest value of an integer type has.
fn integer_digits(type_name: &str) -> Option<u32> {
    match type_name {
        "SMALLINT" => Some(5),
        "INTEGER" => Some(10),
        "BIGINT" => Some(19),
        _ => None,
    }
}

/// Quotes an identifier, so names are taken literally and never parsed as SQL.
fn quote(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn quote_all(identifiers: &[String]) -> String {
    identifiers
        .iter()
        .map(|identifier| quote(identifier))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::test::{database, unique_table};

    fn declared() -> Table {
        Table::new("users")
            .column(Column::new("id", ColumnType::Text))
            .column(Column::new("email", ColumnType::Varchar(200)).not_null())
            .column(
                Column::new("logins", ColumnType::BigInt)
                    .not_null()
                    .default_sql("0"),
            )
            .primary_key(["id"])
            .index(Index::new("by_email", ["email"]).unique())
    }

    fn column(name: &str, column_type: &str, nullable: bool) -> ExistingColumn {
        ExistingColumn {
            name: name.to_owned(),
            column_type: column_type.to_owned(),
            nullable,
        }
    }

    fn matching() -> ExistingTable {
        ExistingTable {
            columns: vec![
                column("id", "TEXT", false),
                column("email", "VARCHAR(200)", false),
                column("logins", "BIGINT", false),
            ],
            primary_key: Some(("users_pkey".to_owned(), vec!["id".to_owned()])),
            indices: vec![ExistingIndex {
                name: "users_by_email".to_owned(),
                columns: vec!["email".to_owned()],
                unique: true,
            }],
        }
    }

    #[test]
    fn a_missing_table_is_created_with_its_indices() {
        let changes = diff(&declared(), None);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].label, "Table 'users' must be created");
        assert_eq!(
            changes[0].sql,
            "CREATE TABLE \"users\" (\n    \"id\" TEXT NOT NULL,\n    \"email\" VARCHAR(200) NOT NULL,\n    \"logins\" BIGINT NOT NULL DEFAULT 0,\n    PRIMARY KEY (\"id\")\n)"
        );
        assert_eq!(
            changes[1].sql,
            "CREATE UNIQUE INDEX \"users_by_email\" ON \"users\" (\"email\")"
        );
        assert!(changes.iter().all(|change| !change.data_loss_expected));
    }

    #[test]
    fn a_matching_table_needs_nothing() {
        assert!(diff(&declared(), Some(&matching())).is_empty());
    }

    #[test]
    fn a_missing_column_is_added() {
        let table = declared().column(Column::new("name", ColumnType::Text).not_null());
        let changes = diff(&table, Some(&matching()));
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0].sql,
            "ALTER TABLE \"users\" ADD COLUMN \"name\" TEXT NOT NULL"
        );
        assert!(changes[0].label.contains("fails if 'users' has rows"));
        assert!(!changes[0].data_loss_expected);
    }

    #[test]
    fn an_undeclared_column_is_dropped_with_data_loss() {
        let mut existing = matching();
        existing.columns.push(column("legacy", "TEXT", true));
        let changes = diff(&declared(), Some(&existing));
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0].sql,
            "ALTER TABLE \"users\" DROP COLUMN \"legacy\""
        );
        assert!(changes[0].data_loss_expected);
    }

    #[test]
    fn widening_a_type_keeps_data_and_narrowing_does_not() {
        let mut existing = matching();
        existing.columns[1] = column("email", "VARCHAR(100)", false);
        existing.columns[2] = column("logins", "INTEGER", false);
        let changes = diff(&declared(), Some(&existing));
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().all(|change| !change.data_loss_expected));
        assert_eq!(
            changes[1].sql,
            "ALTER TABLE \"users\" ALTER COLUMN \"logins\" TYPE BIGINT USING \"logins\"::BIGINT"
        );

        existing.columns[1] = column("email", "VARCHAR(300)", false);
        let changes = diff(&declared(), Some(&existing));
        assert!(changes[0].data_loss_expected);
    }

    #[test]
    fn nullability_follows_the_declaration() {
        let mut existing = matching();
        existing.columns[1] = column("email", "VARCHAR(200)", true);
        let changes = diff(&declared(), Some(&existing));
        assert_eq!(
            changes[0].sql,
            "ALTER TABLE \"users\" ALTER COLUMN \"email\" SET NOT NULL"
        );

        let table = Table::new("users")
            .column(Column::new("id", ColumnType::Text))
            .column(Column::new("email", ColumnType::Varchar(200)))
            .column(Column::new("logins", ColumnType::BigInt).not_null())
            .primary_key(["id"])
            .index(Index::new("by_email", ["email"]).unique());
        let changes = diff(&table, Some(&matching()));
        assert_eq!(
            changes[0].sql,
            "ALTER TABLE \"users\" ALTER COLUMN \"email\" DROP NOT NULL"
        );
    }

    #[test]
    fn indices_are_rebuilt_dropped_and_created() {
        let mut existing = matching();
        existing.indices[0].unique = false;
        existing.indices.push(ExistingIndex {
            name: "users_old".to_owned(),
            columns: vec!["logins".to_owned()],
            unique: false,
        });
        existing.indices.push(ExistingIndex {
            name: "hand_made".to_owned(),
            columns: vec!["logins".to_owned()],
            unique: false,
        });
        let table = declared().index(Index::new("by_logins", ["logins", "id"]));
        let changes = diff(&table, Some(&existing));
        let sql = changes.iter().map(|c| c.sql.as_str()).collect::<Vec<_>>();
        assert_eq!(
            sql,
            vec![
                "DROP INDEX \"users_by_email\";\nCREATE UNIQUE INDEX \"users_by_email\" ON \"users\" (\"email\")",
                "DROP INDEX \"users_old\"",
                "CREATE INDEX \"users_by_logins\" ON \"users\" (\"logins\", \"id\")",
            ]
        );
    }

    #[test]
    fn a_changed_primary_key_is_replaced() {
        let table = declared().primary_key(["id", "email"]);
        let changes = diff(&table, Some(&matching()));
        assert_eq!(
            changes[0].sql,
            "ALTER TABLE \"users\" DROP CONSTRAINT \"users_pkey\";\nALTER TABLE \"users\" ADD PRIMARY KEY (\"id\", \"email\")"
        );
    }

    #[test]
    fn decimals_widen_only_when_no_digit_is_lost() {
        let wider = ColumnType::Decimal(14, 4);
        assert!(is_widening("NUMERIC(12,2)", &wider));
        assert!(is_widening("INTEGER", &wider));
        assert!(
            !is_widening("BIGINT", &wider),
            "19 integer digits do not fit in 10"
        );
        assert!(
            !is_widening("NUMERIC(12,2)", &ColumnType::Decimal(12, 1)),
            "rounds a digit"
        );
        assert!(
            !is_widening("NUMERIC(12,2)", &ColumnType::Decimal(12, 4)),
            "cuts integer digits"
        );
        assert!(is_widening("NUMERIC(12,2)", &ColumnType::Numeric));
        assert!(is_widening("BIGINT", &ColumnType::Numeric));
        assert!(!is_widening("NUMERIC", &ColumnType::Decimal(38, 10)));
        assert!(!is_widening("DOUBLE PRECISION", &ColumnType::Numeric));
    }

    #[test]
    fn a_decimal_column_is_declared_with_precision_and_scale() {
        let table = Table::new("prices")
            .column(Column::new("id", ColumnType::Text))
            .column(Column::new("amount", ColumnType::Decimal(12, 2)).not_null())
            .column(Column::new("rate", ColumnType::Numeric))
            .primary_key(["id"]);
        assert_eq!(
            diff(&table, None)[0].sql,
            "CREATE TABLE \"prices\" (\n    \"id\" TEXT NOT NULL,\n    \"amount\" NUMERIC(12,2) NOT NULL,\n    \"rate\" NUMERIC,\n    PRIMARY KEY (\"id\")\n)"
        );
    }

    #[tokio::test]
    async fn decimal_columns_converge_and_narrowing_is_withheld() {
        let Some(db) = database().await else { return };
        let name = unique_table("schema_decimals");
        let declare = |amount: ColumnType| {
            Table::new(&name)
                .column(Column::new("id", ColumnType::Text))
                .column(Column::new("amount", amount))
                .column(Column::new("rate", ColumnType::Numeric))
                .primary_key(["id"])
        };

        let _ = db
            .ensure_exists(&declare(ColumnType::Decimal(10, 2)))
            .await
            .unwrap();
        assert!(
            db.schema_changes(&declare(ColumnType::Decimal(10, 2)))
                .await
                .unwrap()
                .is_empty(),
            "a NUMERIC(p,s) column must read back as declared"
        );

        let widened = db
            .ensure_exists(&declare(ColumnType::Decimal(14, 4)))
            .await
            .unwrap();
        assert_eq!(widened.applied.len(), 1);
        assert!(widened.is_complete());

        let narrowed = db
            .ensure_exists(&declare(ColumnType::Decimal(14, 2)))
            .await
            .unwrap();
        assert!(narrowed.applied.is_empty());
        assert_eq!(narrowed.withheld.len(), 1);
        assert!(narrowed.withheld[0].data_loss_expected);

        db.client()
            .await
            .unwrap()
            .batch_execute(&format!("DROP TABLE \"{name}\""))
            .await
            .unwrap();
    }

    #[test]
    fn identifiers_are_quoted() {
        assert_eq!(quote("we\"ird"), "\"we\"\"ird\"");
    }

    #[tokio::test]
    async fn ensure_exists_converges_and_withholds_data_loss() {
        let Some(db) = database().await else { return };
        let name = unique_table("schema_converges");
        let table = Table::new(&name)
            .column(Column::new("id", ColumnType::Text))
            .column(Column::new("email", ColumnType::Varchar(100)).not_null())
            .column(Column::new("legacy", ColumnType::Text))
            .primary_key(["id"])
            .index(Index::new("by_email", ["email"]).unique());

        let created = db.ensure_exists(&table).await.unwrap();
        assert_eq!(created.applied.len(), 2);
        assert!(created.is_complete());
        assert!(db.schema_changes(&table).await.unwrap().is_empty());

        let evolved = Table::new(&name)
            .column(Column::new("id", ColumnType::Text))
            .column(Column::new("email", ColumnType::Text).not_null())
            .column(
                Column::new("logins", ColumnType::BigInt)
                    .not_null()
                    .default_sql("0"),
            )
            .primary_key(["id"])
            .index(Index::new("by_email", ["email"]))
            .index(Index::new("by_logins", ["logins"]));
        let sync = db.ensure_exists(&evolved).await.unwrap();
        assert_eq!(sync.applied.len(), 4, "{:#?}", sync.applied);
        assert_eq!(sync.withheld.len(), 1);
        assert!(sync.withheld[0].sql.contains("DROP COLUMN \"legacy\""));

        db.apply(&sync.withheld).await.unwrap();
        assert!(db.schema_changes(&evolved).await.unwrap().is_empty());

        db.client()
            .await
            .unwrap()
            .batch_execute(&format!("DROP TABLE \"{name}\""))
            .await
            .unwrap();
    }
}
