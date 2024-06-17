-- +goose Up
-- +goose StatementBegin
alter type sgroups.i4mr_any_intersect_state
       add attribute nulls int cascade;

create or replace function sgroups.i4mr_any_intersect_s(s sgroups.i4mr_any_intersect_state, val int4multirange)
    returns sgroups.i4mr_any_intersect_state
as $$
select case
       when val is null
            then ROW((s).overlapped, (s).state, (s).nulls + 1)::sgroups.i4mr_any_intersect_state
       when (s).state && val
            then ROW(true, (s).state * val, (s).nulls)::sgroups.i4mr_any_intersect_state
       else ROW((s).overlapped, (s).state + val, (s).nulls)::sgroups.i4mr_any_intersect_state
       end;
$$ language sql immutable;

create or replace function sgroups.i4mr_any_intersect_f(v sgroups.i4mr_any_intersect_state)
    returns boolean
as $$
    select (v).overlapped or (v).nulls > 1 or ( (v).nulls > 0 and lower((v).state) is not null );
$$ language sql immutable strict;


create or replace aggregate sgroups.i4mr_any_intersect(int4multirange) (
    stype = sgroups.i4mr_any_intersect_state,
    sfunc = sgroups.i4mr_any_intersect_s,
    finalfunc = sgroups.i4mr_any_intersect_f,
    initcond = '(false, "{}", 0)'
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT no-down-scenarion;
-- +goose StatementEnd
