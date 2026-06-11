-- Create the documents table
CREATE TABLE IF NOT EXISTS public.documents (
    key text PRIMARY KEY,
    collection text NOT NULL,
    doc_id text NOT NULL,
    data text,
    created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Index for fast collection lookups
CREATE INDEX IF NOT EXISTS idx_documents_collection ON public.documents(collection);

-- Enable Row Level Security (RLS)
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;

-- Allow all actions for the service_role and authenticated users
CREATE POLICY "Allow all for authenticated/service_role" ON public.documents
    FOR ALL
    TO authenticated, service_role
    USING (true)
    WITH CHECK (true);

-- PL/pgSQL Function for atomic rate limit checks
CREATE OR REPLACE FUNCTION public.check_and_update_rate_limit(
    p_key text,
    p_collection text,
    p_doc_id text,
    p_now double precision,
    p_window_secs double precision,
    p_requests_limit integer
) RETURNS boolean AS $$
DECLARE
    v_data jsonb;
    v_timestamps double precision[];
    v_filtered_timestamps double precision[];
    v_t double precision;
BEGIN
    -- Get existing document or create empty JSON
    SELECT (data::jsonb) INTO v_data FROM public.documents WHERE key = p_key;
    IF v_data IS NULL THEN
        v_data := '{}'::jsonb;
    END IF;

    -- Extract timestamps array
    IF v_data ? 'timestamps' THEN
        -- Convert JSON array to PG array
        SELECT array_agg(val::double precision) INTO v_timestamps
        FROM jsonb_array_elements_text(v_data -> 'timestamps') AS val;
    ELSE
        v_timestamps := ARRAY[]::double precision[];
    END IF;

    -- Filter old timestamps
    v_filtered_timestamps := ARRAY[]::double precision[];
    IF v_timestamps IS NOT NULL THEN
        FOREACH v_t IN ARRAY v_timestamps LOOP
            IF p_now - v_t < p_window_secs THEN
                v_filtered_timestamps := array_append(v_filtered_timestamps, v_t);
            END IF;
        END LOOP;
    END IF;

    -- Check limit
    IF array_length(v_filtered_timestamps, 1) >= p_requests_limit THEN
        RETURN FALSE;
    END IF;

    -- Add current timestamp
    v_filtered_timestamps := array_append(v_filtered_timestamps, p_now);

    -- Build new JSON data
    v_data := jsonb_set(v_data, '{timestamps}', to_jsonb(v_filtered_timestamps));

    -- Insert or update
    INSERT INTO public.documents (key, collection, doc_id, data)
    VALUES (p_key, p_collection, p_doc_id, v_data::text)
    ON CONFLICT (key) DO UPDATE
    SET data = EXCLUDED.data;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
