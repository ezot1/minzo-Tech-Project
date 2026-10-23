SET local check_function_bodies = off;

CREATE EXTENSION "pg_cron";

CREATE EXTENSION "pg_trgm" SCHEMA "extensions";

CREATE EXTENSION "postgis" SCHEMA "extensions";

CREATE EXTENSION "vector" SCHEMA "extensions";

CREATE TABLE "public"."audit_log" (
  "id"           bigint                   GENERATED ALWAYS AS IDENTITY NOT NULL,
  "admin_id"     uuid,
  "action"       text                     NOT NULL,
  "target_table" text                     NOT NULL,
  "target_id"    uuid,
  "details"      jsonb,
  "created_at"   timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "audit_log_pkey" PRIMARY KEY (id)
);

ALTER TABLE "public"."audit_log"
  ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE "public"."audit_log" FROM "anon";

CREATE TABLE "public"."businesses" (
  "id"          uuid   NOT NULL DEFAULT gen_random_uuid(),
  "owner_id"    uuid,
  "name"        text   NOT NULL,
  "category"    text   NOT NULL DEFAULT 'health_facility'::text,
  "description" text,
  "street"      text,
  "town"        text,
  "county"      text,
  "address"     text,
  "phones"      text[] NOT NULL DEFAULT '{}'::text[],
  "website"     text,
  "email"       text,
  CONSTRAINT "businesses_pkey" PRIMARY KEY (id)
);

ALTER TABLE "public"."businesses"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."follows" (
  "user_id"     uuid                     NOT NULL,
  "business_id" uuid                     NOT NULL,
  "created_at"  timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "follows_pkey" PRIMARY KEY (user_id, business_id)
);

ALTER TABLE "public"."follows"
  ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE "public"."follows" FROM "anon";

CREATE TABLE "public"."messages" (
  "id"          uuid                     NOT NULL DEFAULT gen_random_uuid(),
  "business_id" uuid                     NOT NULL,
  "sender_id"   uuid,
  "body"        text                     NOT NULL,
  "is_read"     boolean                  NOT NULL DEFAULT false,
  "created_at"  timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "messages_body_check" CHECK (((char_length(body) >= 1) AND (char_length(body) <= 2000))),
  CONSTRAINT "messages_pkey" PRIMARY KEY (id)
);

ALTER TABLE "public"."messages"
  ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE "public"."messages" FROM "anon";

CREATE TABLE "public"."profiles" (
  "id" uuid NOT NULL,
  CONSTRAINT "profiles_pkey" PRIMARY KEY (id)
);

ALTER TABLE "public"."profiles"
  ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE "public"."profiles" FROM "anon";

CREATE TABLE "public"."reviews" (
  "id"           uuid     NOT NULL DEFAULT gen_random_uuid(),
  "business_id"  uuid     NOT NULL,
  "user_id"      uuid     NOT NULL,
  "stars"        smallint NOT NULL,
  "body"         text     NOT NULL,
  "is_anonymous" boolean  NOT NULL DEFAULT false,
  CONSTRAINT "reviews_body_check" CHECK (((char_length(body) >= 1) AND (char_length(body) <= 2000))),
  CONSTRAINT "reviews_pkey" PRIMARY KEY (id),
  CONSTRAINT "reviews_stars_check" CHECK (((stars >= 1) AND (stars <= 5)))
);

ALTER TABLE "public"."reviews"
  ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE "public"."reviews" FROM "anon";

CREATE TYPE "public"."geo_precision" AS ENUM (
  'exact',
  'street',
  'town',
  'county',
  'placeholder'
);

CREATE TYPE "public"."review_status" AS ENUM (
  'active',
  'hidden',
  'archived'
);

ALTER TABLE "public"."reviews"
  ADD COLUMN "status" public.review_status NOT NULL DEFAULT 'active'::public.review_status;

ALTER TABLE "public"."reviews"
  ADD COLUMN "created_at" timestamp WITH time zone NOT NULL DEFAULT now();

CREATE TYPE "public"."user_role" AS ENUM (
  'public',
  'business',
  'admin'
);

ALTER TABLE "public"."profiles"
  ADD COLUMN "role" public.user_role NOT NULL DEFAULT 'public'::public.user_role;

ALTER TABLE "public"."profiles"
  ADD COLUMN "display_name" text;

ALTER TABLE "public"."profiles"
  ADD COLUMN "phone" text;

ALTER TABLE "public"."profiles"
  ADD COLUMN "created_at" timestamp WITH time zone NOT NULL DEFAULT now();

CREATE TYPE "public"."verification_status" AS ENUM (
  'unverified',
  'pending',
  'verified',
  'rejected'
);

ALTER TABLE "public"."businesses"
  ADD COLUMN "verification_status" public.verification_status NOT NULL DEFAULT 'unverified'::public.verification_status;

ALTER TABLE "public"."businesses"
  ADD COLUMN "registration_doc_path" text;

ALTER TABLE "public"."businesses"
  ADD COLUMN "avg_rating" numeric(2,1);

ALTER TABLE "public"."businesses"
  ADD COLUMN "review_count" integer NOT NULL DEFAULT 0;

ALTER TABLE "public"."businesses"
  ADD COLUMN "is_demo" boolean NOT NULL DEFAULT false;

ALTER TABLE "public"."businesses"
  ADD COLUMN "source" text;

ALTER TABLE "public"."businesses"
  ADD COLUMN "created_at" timestamp WITH time zone NOT NULL DEFAULT now();

ALTER TABLE "public"."businesses"
  ADD COLUMN "search" tsvector GENERATED ALWAYS AS
    (to_tsvector('simple'::regconfig, ((((((((COALESCE(name, ''::text) || ' '::text) || COALESCE(category, ''::text)) || ' '::text) || COALESCE(street, ''::text)) || ' '::text) ||
    COALESCE(town, ''::text)) || ' '::text) || COALESCE(county, ''::text)))) STORED;

ALTER TABLE "public"."businesses"
  ADD COLUMN "latitude" double precision;

ALTER TABLE "public"."businesses"
  ADD COLUMN "longitude" double precision;

CREATE OR REPLACE FUNCTION public.admin_set_review_status (
  p_review uuid,
  p_status public.review_status
)
  RETURNS void
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public'
  AS $function$
begin
  if not is_admin() then raise exception 'not allowed' using errcode = '42501'; end if;
  update reviews set status = p_status where id = p_review;
end $function$;

REVOKE ALL ON FUNCTION "public"."admin_set_review_status"(uuid, public.review_status) FROM PUBLIC, "anon";

CREATE OR REPLACE FUNCTION public.admin_set_verification (
  p_business uuid,
  p_status   public.verification_status
)
  RETURNS void
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public'
  AS $function$
begin
  if not is_admin() then raise exception 'not allowed' using errcode = '42501'; end if;
  update businesses set verification_status = p_status where id = p_business;
end $function$;

REVOKE ALL ON FUNCTION "public"."admin_set_verification"(uuid, public.verification_status) FROM PUBLIC, "anon";

CREATE OR REPLACE FUNCTION public.archive_expired_reviews()
  RETURNS integer
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public'
  AS $function$
declare n int;
begin
  update reviews set status = 'archived'
   where status = 'active' and created_at < now() - rating_window();
  get diagnostics n = row_count;
  return n;
end $function$;

REVOKE ALL ON FUNCTION "public"."archive_expired_reviews"() FROM PUBLIC, "anon", "authenticated";

CREATE OR REPLACE FUNCTION public.audit_admin_change()
  RETURNS TRIGGER
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public'
  AS $function$
declare v_id uuid; v_details jsonb;
begin
  if not is_admin() then return null; end if;
  if tg_op = 'DELETE' then
    v_id := old.id;
    v_details := jsonb_build_object('old', to_jsonb(old));
  else
    -- skip rating-only updates caused by the recalc trigger
    if (to_jsonb(new) - 'avg_rating' - 'review_count' - 'search')
     = (to_jsonb(old) - 'avg_rating' - 'review_count' - 'search') then
      return null;
    end if;
    v_id := new.id;
    v_details := jsonb_build_object('old', to_jsonb(old), 'new', to_jsonb(new));
  end if;
  insert into audit_log (admin_id, action, target_table, target_id, details)
  values (auth.uid(), lower(tg_op), tg_table_name, v_id, v_details);
  return null;
end $function$;

CREATE OR REPLACE FUNCTION public.businesses_before_write()
  RETURNS TRIGGER
  LANGUAGE plpgsql
  AS $function$
begin
  if current_user = 'authenticated' and not is_admin() then
    if tg_op = 'INSERT' then
      new.verification_status := 'pending';
    elsif new.registration_doc_path is distinct from old.registration_doc_path
          and old.verification_status in ('unverified', 'rejected') then
      new.verification_status := 'pending';
    end if;
  end if;
  return new;
end $function$;

CREATE OR REPLACE FUNCTION public.handle_new_user()
  RETURNS TRIGGER
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public'
  AS $function$
begin
  insert into profiles (id, display_name, phone, role)
  values (
    new.id,
    new.raw_user_meta_data ->> 'display_name',
    new.phone,
    case when new.raw_user_meta_data ->> 'account_type' = 'business'
         then 'business'::user_role else 'public'::user_role end
  );
  return new;
end $function$;

CREATE OR REPLACE FUNCTION public.is_admin()
  RETURNS boolean
  LANGUAGE sql
  STABLE
  SECURITY DEFINER
  SET search_path TO 'public'
  AS $function$
  select exists (select 1 from profiles where id = auth.uid() and role = 'admin');
$function$;

CREATE OR REPLACE FUNCTION public.my_role()
  RETURNS public.user_role
  LANGUAGE sql
  STABLE
  SECURITY DEFINER
  SET search_path TO 'public'
  AS $function$
  select role from profiles where id = auth.uid();
$function$;

CREATE OR REPLACE FUNCTION public.rating_window()
  RETURNS interval
  LANGUAGE sql
  IMMUTABLE
  AS $function$ select interval '24 months' $function$;

CREATE OR REPLACE FUNCTION public.recalc_rating (
  p_business uuid
)
  RETURNS void
  LANGUAGE sql
  SECURITY DEFINER
  SET search_path TO 'public'
  AS $function$
  update businesses b
     set avg_rating = s.avg_stars,
         review_count = s.cnt
    from (
      select round(avg(stars)::numeric, 1) as avg_stars, count(*)::int as cnt
        from reviews
       where business_id = p_business
         and status = 'active'
         and created_at > now() - rating_window()
    ) s
   where b.id = p_business;
$function$;

REVOKE ALL ON FUNCTION "public"."recalc_rating"(uuid) FROM PUBLIC, "anon", "authenticated";

CREATE OR REPLACE FUNCTION public.reviews_after_change()
  RETURNS TRIGGER
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public'
  AS $function$
begin
  if tg_op = 'DELETE' then
    perform recalc_rating(old.business_id);
  else
    perform recalc_rating(new.business_id);
  end if;
  return null;
end $function$;

CREATE OR REPLACE FUNCTION public.rls_auto_enable()
  RETURNS event_trigger
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'pg_catalog'
  AS $function$
DECLARE
  cmd record;
  tbl name;
BEGIN
  FOR cmd IN
    SELECT *
    FROM pg_event_trigger_ddl_commands()
    WHERE command_tag IN ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO')
      AND object_type IN ('table','partitioned table')
  LOOP
     IF cmd.schema_name IS NOT NULL AND cmd.schema_name IN ('public') AND cmd.schema_name NOT IN ('pg_catalog','information_schema') AND cmd.schema_name NOT LIKE 'pg_toast%' AND cmd.schema_name NOT LIKE 'pg_temp%' THEN
      BEGIN
        SELECT c.relname INTO tbl FROM pg_catalog.pg_class c WHERE c.oid = cmd.objid;
        EXECUTE format('alter table if exists %I.%I enable row level security', cmd.schema_name, tbl);
        RAISE LOG 'rls_auto_enable: enabled RLS on %', cmd.object_identity;
      EXCEPTION
        WHEN OTHERS THEN
          RAISE LOG 'rls_auto_enable: failed to enable RLS on %', cmd.object_identity;
      END;
     ELSE
        RAISE LOG 'rls_auto_enable: skip % (either system schema or not in enforced list: %.)', cmd.object_identity, cmd.schema_name;
     END IF;
  END LOOP;
END;
$function$;

CREATE OR REPLACE FUNCTION public.search_businesses (
  p_query      text             DEFAULT NULL::text,
  p_lat        double precision DEFAULT NULL::double precision,
  p_lng        double precision DEFAULT NULL::double precision,
  p_radius_km  double precision DEFAULT 25,
  p_category   text             DEFAULT NULL::text,
  p_min_rating numeric          DEFAULT NULL::numeric,
  p_limit      integer          DEFAULT 30
)
  RETURNS TABLE (
    id                  uuid,
    name                text,
    category            text,
    street              text,
    town                text,
    county              text,
    phones              text[],
    verification_status public.verification_status,
    avg_rating          numeric,
    review_count        integer,
    geo_precision       public.geo_precision,
    lat                 double precision,
    lng                 double precision,
    distance_m          double precision
  )
  LANGUAGE sql
  STABLE
  SET search_path TO 'public', 'extensions'
  AS $function$
  with origin as (
    select case when p_lat is null or p_lng is null then null
                else st_setsrid(st_makepoint(p_lng, p_lat), 4326)::geography end as g
  )
  select b.id, b.name, b.category, b.street, b.town, b.county, b.phones,
         b.verification_status, b.avg_rating, b.review_count, b.geo_precision,
         st_y(b.location::geometry), st_x(b.location::geometry),
         case when o.g is not null and b.location is not null
              then st_distance(b.location, o.g) end
    from businesses b
   cross join origin o
   where (p_category is null or b.category = p_category)
     and (p_min_rating is null or b.avg_rating >= p_min_rating)
     and (coalesce(p_query, '') = ''
          or b.search @@ websearch_to_tsquery('simple', p_query)
          or b.name % p_query or b.street % p_query or b.town % p_query)
     and (o.g is null or st_dwithin(b.location, o.g, p_radius_km * 1000))
   order by 14 asc nulls last,
            similarity(b.name, coalesce(p_query, '')) desc,
            b.avg_rating desc nulls last
   limit least(p_limit, 100);
$function$;

ALTER TABLE "public"."businesses"
  ADD CONSTRAINT "businesses_latitude_range" CHECK (((latitude IS NULL) OR ((latitude >= ('-90'::integer)::double precision) AND (latitude <= (90)::double precision))));

ALTER TABLE "public"."businesses"
  ADD CONSTRAINT "businesses_longitude_range" CHECK (((longitude IS NULL) OR ((longitude >= ('-180'::integer)::double precision) AND (longitude <= (180)::double precision))));

ALTER TABLE "public"."follows"
  ADD CONSTRAINT "follows_business_id_fkey" FOREIGN KEY (business_id) REFERENCES public.businesses(id) ON DELETE CASCADE;

ALTER TABLE "public"."messages"
  ADD CONSTRAINT "messages_business_id_fkey" FOREIGN KEY (business_id) REFERENCES public.businesses(id) ON DELETE CASCADE;

ALTER TABLE "public"."profiles"
  ADD CONSTRAINT "profiles_id_fkey" FOREIGN KEY (id) REFERENCES auth.users(id) ON DELETE CASCADE;

ALTER TABLE "public"."businesses"
  ADD CONSTRAINT "businesses_owner_id_fkey" FOREIGN KEY (owner_id) REFERENCES public.profiles(id) ON DELETE SET NULL;

ALTER TABLE "public"."follows"
  ADD CONSTRAINT "follows_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE CASCADE;

ALTER TABLE "public"."messages"
  ADD CONSTRAINT "messages_sender_id_fkey" FOREIGN KEY (sender_id) REFERENCES public.profiles(id) ON DELETE SET NULL;

ALTER TABLE "public"."reviews"
  ADD CONSTRAINT "reviews_business_id_fkey" FOREIGN KEY (business_id) REFERENCES public.businesses(id) ON DELETE CASCADE;

ALTER TABLE "public"."reviews"
  ADD CONSTRAINT "reviews_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE CASCADE;

CREATE VIEW "public"."public_reviews" WITH (security_barrier=true, security_invoker=true) AS  SELECT r.id,
    r.business_id,
    r.stars,
    r.body,
    r.created_at,
        CASE
            WHEN r.is_anonymous THEN 'Anonymous'::text
            ELSE COALESCE(p.display_name, 'User'::text)
        END AS author_name,
    (r.user_id = auth.uid()) AS is_mine
   FROM (public.reviews r
     LEFT JOIN public.profiles p ON ((p.id = r.user_id)))
  WHERE ((r.status = 'active'::public.review_status) AND (r.created_at > (now() - public.rating_window())));

CREATE INDEX businesses_category_idx ON public.businesses USING btree (category);

CREATE INDEX businesses_name_trgm ON public.businesses USING gin (name extensions.gin_trgm_ops);

CREATE INDEX businesses_search_idx ON public.businesses USING gin (search);

CREATE INDEX messages_business_idx ON public.messages USING btree (business_id, created_at DESC);

CREATE INDEX reviews_business_idx ON public.reviews USING btree (business_id, status, created_at);

CREATE UNIQUE INDEX reviews_one_active ON public.reviews USING btree (business_id, user_id)
  WHERE (status = 'active'::public.review_status);

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user();

CREATE TRIGGER businesses_audit
  AFTER DELETE OR UPDATE ON public.businesses
  FOR EACH ROW
  EXECUTE FUNCTION public.audit_admin_change();

CREATE TRIGGER businesses_before_write
  BEFORE INSERT OR UPDATE ON public.businesses
  FOR EACH ROW
  EXECUTE FUNCTION public.businesses_before_write();

CREATE TRIGGER reviews_after_change
  AFTER INSERT OR DELETE OR UPDATE ON public.reviews
  FOR EACH ROW
  EXECUTE FUNCTION public.reviews_after_change();

CREATE TRIGGER reviews_audit
  AFTER DELETE OR UPDATE ON public.reviews
  FOR EACH ROW
  EXECUTE FUNCTION public.audit_admin_change();

CREATE POLICY "audit_admin_read" ON "public"."audit_log"
  FOR SELECT
  TO PUBLIC
  USING (public.is_admin());

CREATE POLICY "businesses_delete" ON "public"."businesses"
  FOR DELETE
  TO PUBLIC
  USING (public.is_admin());

CREATE POLICY "businesses_insert" ON "public"."businesses"
  FOR INSERT
  TO PUBLIC
  WITH CHECK ((((owner_id = auth.uid()) AND (public.my_role() = 'business'::public.user_role)) OR public.is_admin()));

CREATE POLICY "businesses_read" ON "public"."businesses"
  FOR SELECT
  TO PUBLIC
  USING (((verification_status = ANY (ARRAY['unverified'::public.verification_status, 'verified'::public.verification_status])) OR (owner_id = auth.uid()) OR public.is_admin()));

CREATE POLICY "businesses_update" ON "public"."businesses"
  FOR UPDATE
  TO PUBLIC
  USING (((owner_id = auth.uid()) OR public.is_admin()))
  WITH CHECK (((owner_id = auth.uid()) OR public.is_admin()));

CREATE POLICY "follows_owner_read" ON "public"."follows"
  FOR SELECT
  TO PUBLIC
  USING ((EXISTS ( SELECT 1
   FROM public.businesses b
  WHERE ((b.id = follows.business_id) AND (b.owner_id = auth.uid())))));

CREATE POLICY "follows_own" ON "public"."follows"
  FOR ALL
  TO PUBLIC
  USING ((user_id = auth.uid()))
  WITH CHECK ((user_id = auth.uid()));

CREATE POLICY "messages_insert" ON "public"."messages"
  FOR INSERT
  TO PUBLIC
  WITH CHECK ((sender_id = auth.uid()));

CREATE POLICY "messages_mark_read" ON "public"."messages"
  FOR UPDATE
  TO PUBLIC
  USING ((EXISTS ( SELECT 1
   FROM public.businesses b
  WHERE ((b.id = messages.business_id) AND (b.owner_id = auth.uid())))));

CREATE POLICY "messages_read" ON "public"."messages"
  FOR SELECT
  TO PUBLIC
  USING (((sender_id = auth.uid()) OR public.is_admin() OR (EXISTS ( SELECT 1
   FROM public.businesses b
  WHERE ((b.id = messages.business_id) AND (b.owner_id = auth.uid()))))));

CREATE POLICY "profiles_read" ON "public"."profiles"
  FOR SELECT
  TO PUBLIC
  USING (((id = auth.uid()) OR public.is_admin()));

CREATE POLICY "profiles_update" ON "public"."profiles"
  FOR UPDATE
  TO PUBLIC
  USING ((id = auth.uid()))
  WITH CHECK ((id = auth.uid()));

CREATE POLICY "reviews_delete" ON "public"."reviews"
  FOR DELETE
  TO PUBLIC
  USING (((user_id = auth.uid()) OR public.is_admin()));

CREATE POLICY "reviews_insert" ON "public"."reviews"
  FOR INSERT
  TO PUBLIC
  WITH CHECK (((user_id = auth.uid()) AND (NOT (EXISTS ( SELECT 1
   FROM public.businesses b
  WHERE ((b.id = reviews.business_id) AND (b.owner_id = auth.uid())))))));

CREATE POLICY "reviews_read" ON "public"."reviews"
  FOR SELECT
  TO PUBLIC
  USING (((user_id = auth.uid()) OR public.is_admin()));

CREATE POLICY "reviews_update" ON "public"."reviews"
  FOR UPDATE
  TO PUBLIC
  USING (((user_id = auth.uid()) OR public.is_admin()))
  WITH CHECK (((user_id = auth.uid()) OR public.is_admin()));

CREATE POLICY "docs_read" ON "storage"."objects"
  FOR SELECT
  TO "authenticated"
  USING (((bucket_id = 'registration-docs'::text) AND (((storage.foldername(name))[1] = (auth.uid())::text) OR public.is_admin())));

CREATE POLICY "docs_upload" ON "storage"."objects"
  FOR INSERT
  TO "authenticated"
  WITH CHECK (((bucket_id = 'registration-docs'::text) AND ((storage.foldername(name))[1] = (auth.uid())::text)));

CREATE POLICY "gallery_delete" ON "storage"."objects"
  FOR DELETE
  TO "authenticated"
  USING (((bucket_id = 'gallery'::text) AND (public.is_admin() OR (EXISTS ( SELECT 1
   FROM public.businesses b
  WHERE (((b.id)::text = (storage.foldername(b.name))[1]) AND (b.owner_id = auth.uid())))))));

CREATE POLICY "gallery_read" ON "storage"."objects"
  FOR SELECT
  TO PUBLIC
  USING ((bucket_id = 'gallery'::text));

CREATE POLICY "gallery_upload" ON "storage"."objects"
  FOR INSERT
  TO "authenticated"
  WITH CHECK (((bucket_id = 'gallery'::text) AND (EXISTS ( SELECT 1
   FROM public.businesses b
  WHERE (((b.id)::text = (storage.foldername(b.name))[1]) AND (b.owner_id = auth.uid()))))));

CREATE EVENT TRIGGER "ensure_rls"
  ON ddl_command_end
  WHEN TAG IN ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO')
  EXECUTE FUNCTION "public"."rls_auto_enable"();

COMMENT ON EXTENSION "pg_cron" IS 'Job scheduler for PostgreSQL';

COMMENT ON EXTENSION "pg_trgm" IS 'text similarity measurement and index searching based on trigrams';

COMMENT ON EXTENSION "postgis" IS 'PostGIS geometry and geography spatial types and functions';

COMMENT ON EXTENSION "vector" IS 'vector data type and ivfflat and hnsw access methods';

GRANT EXECUTE ON FUNCTION "public"."admin_set_review_status"(uuid, public.review_status) TO "authenticated";

REVOKE ALL ON FUNCTION "public"."admin_set_review_status"(uuid, public.review_status) FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."admin_set_review_status"(uuid, public.review_status) TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."admin_set_review_status"(uuid, public.review_status) TO "service_role";

GRANT EXECUTE ON FUNCTION "public"."admin_set_verification"(uuid, public.verification_status) TO "authenticated";

REVOKE ALL ON FUNCTION "public"."admin_set_verification"(uuid, public.verification_status) FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."admin_set_verification"(uuid, public.verification_status) TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."admin_set_verification"(uuid, public.verification_status) TO "service_role";

REVOKE ALL ON FUNCTION "public"."archive_expired_reviews"() FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."archive_expired_reviews"() TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."archive_expired_reviews"() TO "service_role";

GRANT EXECUTE ON FUNCTION "public"."audit_admin_change"() TO PUBLIC, "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."audit_admin_change"() FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."audit_admin_change"() TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."audit_admin_change"() TO "service_role";

GRANT EXECUTE ON FUNCTION "public"."businesses_before_write"() TO PUBLIC, "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."businesses_before_write"() FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."businesses_before_write"() TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."businesses_before_write"() TO "service_role";

GRANT EXECUTE ON FUNCTION "public"."handle_new_user"() TO PUBLIC, "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."handle_new_user"() FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."handle_new_user"() TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."handle_new_user"() TO "service_role";

GRANT EXECUTE ON FUNCTION "public"."is_admin"() TO PUBLIC, "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."is_admin"() FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."is_admin"() TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."is_admin"() TO "service_role";

GRANT EXECUTE ON FUNCTION "public"."my_role"() TO PUBLIC, "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."my_role"() FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."my_role"() TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."my_role"() TO "service_role";

GRANT EXECUTE ON FUNCTION "public"."rating_window"() TO PUBLIC, "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."rating_window"() FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."rating_window"() TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."rating_window"() TO "service_role";

REVOKE ALL ON FUNCTION "public"."recalc_rating"(uuid) FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."recalc_rating"(uuid) TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."recalc_rating"(uuid) TO "service_role";

GRANT EXECUTE ON FUNCTION "public"."reviews_after_change"() TO PUBLIC, "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."reviews_after_change"() FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."reviews_after_change"() TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."reviews_after_change"() TO "service_role";

GRANT EXECUTE ON FUNCTION "public"."rls_auto_enable"() TO PUBLIC, "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."rls_auto_enable"() FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."rls_auto_enable"() TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."rls_auto_enable"() TO "service_role";

GRANT EXECUTE ON FUNCTION "public"."search_businesses"(text, double precision, double precision, double precision, text, numeric, integer) TO PUBLIC, "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."search_businesses"(text, double precision, double precision, double precision, text, numeric, integer) FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."search_businesses"(text, double precision, double precision, double precision, text, numeric, integer) TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."search_businesses"(text, double precision, double precision, double precision, text, numeric, integer) TO "service_role";

REVOKE ALL ON SEQUENCE "public"."audit_log_id_seq" FROM "anon";

GRANT SELECT, UPDATE, USAGE ON SEQUENCE "public"."audit_log_id_seq" TO "anon";

REVOKE ALL ON SEQUENCE "public"."audit_log_id_seq" FROM "authenticated";

GRANT SELECT, UPDATE, USAGE ON SEQUENCE "public"."audit_log_id_seq" TO "authenticated";

REVOKE ALL ON SEQUENCE "public"."audit_log_id_seq" FROM "postgres";

GRANT SELECT, UPDATE, USAGE ON SEQUENCE "public"."audit_log_id_seq" TO "postgres";

REVOKE ALL ON SEQUENCE "public"."audit_log_id_seq" FROM "service_role";

GRANT SELECT, UPDATE, USAGE ON SEQUENCE "public"."audit_log_id_seq" TO "service_role";

REVOKE ALL ON TABLE "public"."audit_log" FROM "authenticated";

GRANT SELECT ON TABLE "public"."audit_log" TO "authenticated";

REVOKE ALL ON TABLE "public"."audit_log" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."audit_log" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."audit_log" TO "service_role";

REVOKE ALL ON TABLE "public"."businesses" FROM "anon";

GRANT SELECT ON TABLE "public"."businesses" TO "anon";

REVOKE ALL ON TABLE "public"."businesses" FROM "authenticated";

REVOKE ALL ("address") ON TABLE "public"."businesses" FROM "authenticated";

GRANT INSERT ("address"), UPDATE ("address") ON TABLE "public"."businesses" TO "authenticated";

REVOKE ALL ("category") ON TABLE "public"."businesses" FROM "authenticated";

GRANT INSERT ("category"), UPDATE ("category") ON TABLE "public"."businesses" TO "authenticated";

REVOKE ALL ("county") ON TABLE "public"."businesses" FROM "authenticated";

GRANT INSERT ("county"), UPDATE ("county") ON TABLE "public"."businesses" TO "authenticated";

REVOKE ALL ("description") ON TABLE "public"."businesses" FROM "authenticated";

GRANT INSERT ("description"), UPDATE ("description") ON TABLE "public"."businesses" TO "authenticated";

REVOKE ALL ("email") ON TABLE "public"."businesses" FROM "authenticated";

GRANT INSERT ("email"), UPDATE ("email") ON TABLE "public"."businesses" TO "authenticated";

REVOKE ALL ("name") ON TABLE "public"."businesses" FROM "authenticated";

GRANT INSERT ("name"), UPDATE ("name") ON TABLE "public"."businesses" TO "authenticated";

REVOKE ALL ("owner_id") ON TABLE "public"."businesses" FROM "authenticated";

GRANT INSERT ("owner_id") ON TABLE "public"."businesses" TO "authenticated";

REVOKE ALL ("phones") ON TABLE "public"."businesses" FROM "authenticated";

GRANT INSERT ("phones"), UPDATE ("phones") ON TABLE "public"."businesses" TO "authenticated";

REVOKE ALL ("registration_doc_path") ON TABLE "public"."businesses" FROM "authenticated";

GRANT INSERT ("registration_doc_path"), UPDATE ("registration_doc_path") ON TABLE "public"."businesses" TO "authenticated";

REVOKE ALL ("street") ON TABLE "public"."businesses" FROM "authenticated";

GRANT INSERT ("street"), UPDATE ("street") ON TABLE "public"."businesses" TO "authenticated";

REVOKE ALL ("town") ON TABLE "public"."businesses" FROM "authenticated";

GRANT INSERT ("town"), UPDATE ("town") ON TABLE "public"."businesses" TO "authenticated";

REVOKE ALL ("website") ON TABLE "public"."businesses" FROM "authenticated";

GRANT INSERT ("website"), UPDATE ("website") ON TABLE "public"."businesses" TO "authenticated";

GRANT DELETE, SELECT ON TABLE "public"."businesses" TO "authenticated";

REVOKE ALL ON TABLE "public"."businesses" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."businesses" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."businesses" TO "service_role";

REVOKE ALL ON TABLE "public"."follows" FROM "authenticated";

GRANT DELETE, INSERT, SELECT ON TABLE "public"."follows" TO "authenticated";

REVOKE ALL ON TABLE "public"."follows" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."follows" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."follows" TO "service_role";

REVOKE ALL ON TABLE "public"."messages" FROM "authenticated";

REVOKE ALL ("body") ON TABLE "public"."messages" FROM "authenticated";

GRANT INSERT ("body") ON TABLE "public"."messages" TO "authenticated";

REVOKE ALL ("business_id") ON TABLE "public"."messages" FROM "authenticated";

GRANT INSERT ("business_id") ON TABLE "public"."messages" TO "authenticated";

REVOKE ALL ("is_read") ON TABLE "public"."messages" FROM "authenticated";

GRANT UPDATE ("is_read") ON TABLE "public"."messages" TO "authenticated";

REVOKE ALL ("sender_id") ON TABLE "public"."messages" FROM "authenticated";

GRANT INSERT ("sender_id") ON TABLE "public"."messages" TO "authenticated";

GRANT SELECT ON TABLE "public"."messages" TO "authenticated";

REVOKE ALL ON TABLE "public"."messages" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."messages" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."messages" TO "service_role";

REVOKE ALL ON TABLE "public"."profiles" FROM "authenticated";

REVOKE ALL ("display_name") ON TABLE "public"."profiles" FROM "authenticated";

GRANT UPDATE ("display_name") ON TABLE "public"."profiles" TO "authenticated";

REVOKE ALL ("phone") ON TABLE "public"."profiles" FROM "authenticated";

GRANT UPDATE ("phone") ON TABLE "public"."profiles" TO "authenticated";

GRANT SELECT ON TABLE "public"."profiles" TO "authenticated";

REVOKE ALL ON TABLE "public"."profiles" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."profiles" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."profiles" TO "service_role";

REVOKE ALL ON TABLE "public"."reviews" FROM "authenticated";

REVOKE ALL ("body") ON TABLE "public"."reviews" FROM "authenticated";

GRANT INSERT ("body"), UPDATE ("body") ON TABLE "public"."reviews" TO "authenticated";

REVOKE ALL ("business_id") ON TABLE "public"."reviews" FROM "authenticated";

GRANT INSERT ("business_id") ON TABLE "public"."reviews" TO "authenticated";

REVOKE ALL ("is_anonymous") ON TABLE "public"."reviews" FROM "authenticated";

GRANT INSERT ("is_anonymous"), UPDATE ("is_anonymous") ON TABLE "public"."reviews" TO "authenticated";

REVOKE ALL ("stars") ON TABLE "public"."reviews" FROM "authenticated";

GRANT INSERT ("stars"), UPDATE ("stars") ON TABLE "public"."reviews" TO "authenticated";

REVOKE ALL ("user_id") ON TABLE "public"."reviews" FROM "authenticated";

GRANT INSERT ("user_id") ON TABLE "public"."reviews" TO "authenticated";

GRANT DELETE, SELECT ON TABLE "public"."reviews" TO "authenticated";

REVOKE ALL ON TABLE "public"."reviews" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."reviews" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."reviews" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."public_reviews" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."public_reviews" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."public_reviews" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."public_reviews" TO "service_role";

SELECT cron.schedule_in_database('archive-expired-reviews', '10 0 * * *', 'select public.archive_expired_reviews();', 'postgres', NULL, true);

