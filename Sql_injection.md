### Connecting to mysql

```bash
mysql -u $username -p$password
```

<aside>
💡

There shouldn't be any spaces between '-p' and the password.

</aside>

### Connecting to a specified host

```bash
mysql -u $username -h $hostname -P $port -p$password
```

### Creating a Database

```bash
CREATE DATABASE $databsename;
```

```bash
SHOW DATABASES;
```

### Tables

```bash
CREATE TABLE $tablename (
		id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
		);
```

```bash
SHOW TABLES;
```

```bash
DESCRIBE $tablename
```

shows table structure

### INSERT Statement

```bash
INSERT INTO $table_name VALUES (column1_value, column2_value, column3_value, ...);
```

```bash
INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');
```

```bash
INSERT INTO $table_name(column2, column3, ...) VALUES (column2_value, column3_value, ...);
```

```bash
INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');
```

```bash
INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');
```

### SELECT Statement

```bash
SELECT * FROM $table_name;
```

```bash
SELECT column1, column2 FROM $table_name;
```

### DROP Statement

```bash
DROP TABLE $table_name;
```

### ALTER Statement

```bash
ALTER TABLE $table_name ADD newColumn INT;
```

```bash
ALTER TABLE $table_name RENAME COLUMN newColumnt TO newerColumn;
```

We can also change a column's datatype with `MODIFY`:

```bash
ALTER TABLE $table_name MODIFY newerColumn DATE;
```

```bash
ALTER TABLE $table_name DROP newerColumn;
```

**UPDATE Statement**

```bash
UPDATE $table_name SET column1 = 'changeme' WHERE id > 1;USE
```
