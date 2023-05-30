--
-- Set up the environment
--

CREATE TABLE public.readonly(
	id integer,
    first_name text,
    last_name text,
    birthday date,
    phone_number text
);
INSERT INTO public.readonly VALUES (1, 'Nice', 'Customer', '1970-03-04', '+886 1234 5678');

CREATE TABLE public.anonymized_successfully(
	id integer,
	val text
);
INSERT INTO public.anonymized_successfully VALUES (1, 'Legal Value');

CREATE TABLE public.readwrite(
	id integer,
	city text
);
INSERT INTO public.readwrite VALUES ('1', 'Paris');

-- Create a malicious function that is legal upon creation
CREATE OR REPLACE FUNCTION
	legal(val text)
RETURNS text AS
$$
BEGIN
	RETURN last_name FROM public.readonly WHERE last_name = val;
END;
$$ language plpgsql;

CREATE OR REPLACE FUNCTION
	my_substr(val text, pos integer, len integer)
RETURNS text AS
$$
BEGIN
	return substr(val, pos, len);
END;
$$ language plpgsql;

LOAD 'pg_anonymize';

SECURITY LABEL FOR pg_anonymize ON COLUMN public.readonly.last_name
    IS $$public.my_substr(last_name, 1, 1) || '*****'$$;
SECURITY LABEL FOR pg_anonymize ON COLUMN public.readonly.birthday
    IS $$date_trunc('year', birthday)::date$$;
SECURITY LABEL FOR pg_anonymize ON COLUMN public.readonly.phone_number
    IS $$regexp_replace(phone_number, '\d', 'X', 'g')$$;
SECURITY LABEL FOR pg_anonymize ON COLUMN public.anonymized_successfully.val
    IS $$REPEAT('X', 5)$$;

-- Make sure our own user is masked
SELECT current_user \gset
SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS 'anonymize';
SET pg_anonymize.enabled = 'on';

-- As a malicious user, modify my_substr function to be writing on data.
-- Such function should fail to be executed by pg_anonymize as write queries are
-- not permitted.
CREATE OR REPLACE FUNCTION
	my_substr(val text, pos integer, len integer)
RETURNS text AS
$$
BEGIN
	CREATE TABLE illegal (a integer);
	return substr(val, pos, len);
END;
$$ language plpgsql;

--
-- Test utility statements
--

-- Verify that utility statements are anonymized
COPY public.readonly TO STDOUT;

-- A masked user should be able to execute write queries on
-- non anonymized tables, i.e. utility statements are not
-- leaking the read-only flag.
CREATE TABLE foo (a int);
DROP TABLE foo;

COPY public.readonly(first_name, phone_number) TO STDOUT;
COPY (SELECT * FROM public.readonly) TO STDOUT;

-- Table illegal should not have been created via my_substr
SELECT count(*) FROM pg_class WHERE relname = 'illegal';

--
-- Nested execution
--

-- Declare an anonymous block and execute it to test second level failure
DO $$
DECLARE
	level_one integer;
	level_two text;
BEGIN
	FOR level_one IN SELECT generate_series(0, 1) LOOP
		RAISE NOTICE 'outer loop %', level_one;
		FOR level_two IN SELECT last_name FROM public.readonly LOOP
			RAISE NOTICE 'inner loop %', level_two; -- Should not be reached
		END LOOP;
	END LOOP;
END;
$$ language plpgsql;

-- Declare an anonymous block and execute it to test first level failure
DO $$
DECLARE
	level_one text;
	level_two integer;
BEGIN
	FOR level_one IN SELECT last_name FROM public.readonly LOOP
		RAISE NOTICE 'outer loop %', level_one; -- Should not be reached
		FOR level_two IN SELECT generate_series(0, 1) LOOP
			RAISE NOTICE 'inner loop %', level_two;
		END LOOP;
	END LOOP;
END;
$$ language plpgsql;

-- Declare an anonymous block and execute it to test leaking readonlyness
DO $$
DECLARE
	level_one integer;
	level_two text;
BEGIN
	FOR level_one IN SELECT generate_series(0, 1) LOOP
		RAISE NOTICE 'outer loop %', level_one;
		FOR level_two IN SELECT val FROM public.anonymized_successfully LOOP
			RAISE NOTICE 'inner loop %', level_two;
		END LOOP;
	END LOOP;

	-- Create table should succeed
	CREATE TABLE plug (a int);
	DROP TABLE plug;
	RAISE NOTICE 'created and dropped table plug';
END;
$$ language plpgsql;

DO $$
DECLARE
	level_one integer;
	level_two text;
BEGIN
	FOR level_two IN SELECT val FROM public.anonymized_successfully LOOP
		RAISE NOTICE 'outer loop %', level_one;
		RAISE NOTICE 'created and dropped table plug';
		FOR level_one IN SELECT generate_series(0, 1) LOOP
			RAISE NOTICE 'inner loop %', level_two;
		END LOOP;
	END LOOP;

	-- Create table should succeed
	CREATE TABLE plug (a int);
	DROP TABLE plug;
	RAISE NOTICE 'created and dropped table plug';
END;
$$ language plpgsql;

-- Table illegal should not have been created via my_substr
SELECT count(*) FROM pg_class WHERE relname = 'illegal';

-- Create and drop table should succeed, i.e. we are not leaking read only flag
CREATE TABLE plug (a int);
DROP TABLE plug;

--
-- Test DML statements
--

-- Explain should succeed, yet explain analyze should fail
EXPLAIN (costs off) SELECT first_name, phone_number FROM public.readonly;
EXPLAIN (analyze) SELECT first_name, phone_number FROM public.readonly;

-- The anonymized function will try to write, so the legal function
-- will also fail.
SELECT legal('Customer');

-- Modify my_substr function to fail during execution run step
CREATE OR REPLACE FUNCTION
	my_substr(val text, pos integer, len integer)
RETURNS text AS
$$
BEGIN
	RAISE EXCEPTION 'should fail during execution run';
END;
$$ language plpgsql;

COPY (SELECT * FROM public.readonly) TO STDOUT;
SELECT first_name, phone_number FROM public.readonly;
SELECT * FROM public.readwrite;

-- Should succeed because no anonymized relation is referenced
INSERT INTO public.readwrite VALUES (2, 'Stockholm');

-- Try to insert into an anonymized relation non anonymized attributes,
-- should fail but it should not crash the server
INSERT INTO public.readonly (id, first_name) VALUES (2, 'Foobar');

-- Just because an anonymized relation is referenced, an anonymized user can not
-- modify a non anonymized relation
INSERT INTO public.readwrite (id, city)
	SELECT id, first_name AS city FROM public.readonly;

-- Try to modify a non anonymized relation from an anonymized relation,
-- should fail
UPDATE public.readwrite SET city = (SELECT first_name as city FROM public.readonly);

-- Should fail because an anonymized relation can not be modified by an
-- anonymized user
WITH cte AS (
	DELETE FROM	public.readonly RETURNING *
)
SELECT * FROM cte;

-- Should fail because an anonymized relation is referenced
WITH cte AS (
	SELECT
		id,
		first_name as city
	FROM
		public.readonly
)
INSERT INTO readwrite SELECT * FROM cte;

-- Materialized cte should also fail because an anonymized
-- relation is referenced
WITH cte AS MATERIALIZED (
	SELECT
		id,
		first_name as city
	FROM
		public.readonly
)
INSERT INTO readwrite SELECT * FROM cte;

-- Create and drop table should succeed, i.e. we are not leaking read only flag
CREATE TABLE plug (a int);
DROP TABLE plug;

SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS NULL;
