LOAD 'pg_anonymize';

-- Remember our own user and verify that the user is unmasked
SELECT current_user \gset
SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS NULL;

-- Create the base relation and add some data to it
CREATE TABLE public.base_relation(id integer,
    name text,
    phone_number text);
INSERT INTO public.base_relation VALUES (1, 'Nol Otta', '+46 080 80808');

-- Create a label for one column
SECURITY LABEL FOR pg_anonymize ON COLUMN public.base_relation.phone_number
    IS $$ regexp_replace(phone_number, '\d', 'X', 'g') $$;

-- Mask our own user
SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS 'anonymize';

-- Masked user should be allowed to create a materialized view
-- on all columns of the base relation
CREATE MATERIALIZED VIEW public.matview_all_visible AS 
	SELECT name FROM public.base_relation WITH NO DATA;

CREATE MATERIALIZED VIEW public.matview_anonymized AS 
	SELECT phone_number FROM public.base_relation WITH NO DATA;

-- Masked user should be allowed to refresh the materialized view
-- when the columns involved do not carry a security label
REFRESH MATERIALIZED VIEW public.matview_all_visible;
SELECT * FROM public.matview_all_visible;

-- Something should happen here, either the user should not be allowed to
-- refresh or the materialized view should acquire the same security label as
-- the base relation
REFRESH MATERIALIZED VIEW public.matview_anonymized;
SELECT * FROM public.matview_anonymized;

-- Verify the contents of the base relation are masked as expected
SELECT * FROM public.base_relation;

-- Verify the contents of the base relation are masked as expected
-- even via a view
CREATE VIEW public.view_relation AS SELECT * FROM public.base_relation;
SELECT * FROM public.view_relation;

-- Unmask our own user
SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS NULL;
