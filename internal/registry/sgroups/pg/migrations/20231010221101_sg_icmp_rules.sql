-- +goose Up
-- +goose StatementBegin
------------------------------- TYPES ---------------------------
drop type if exists sgroups.ip_family cascade;
create type sgroups.ip_family as enum (
    'IPv4',
    'IPv6'
);

drop function if exists sgroups.icmp_type_values_ok(int2[]) cascade;
create or replace function sgroups.icmp_type_values_ok(vals int2[])
   returns boolean
as $$
declare badVal int2;
begin
   select c
     from unnest(vals) as c
    where not (c between 0 and 255)
    limit 1
     into badVal;
   return badVal is null;
end;
$$ language plpgsql immutable strict;

drop domain if exists sgroups.icmp_types cascade;
create domain sgroups.icmp_types
           as int2[]
   constraint validate_icmp_type_values
        check (
            sgroups.icmp_type_values_ok(value)
        )
;

--------------------------------------- TABLES ---------------------------------------

drop table if exists sgroups.tbl_sg_icmp_rule cascade;
create table sgroups.tbl_sg_icmp_rule (
    id bigint generated always as identity primary key,
    ip_v sgroups.ip_family not null,
    types sgroups.icmp_types not null,
    sg bigint not null,
    logs boolean not null,
    trace boolean not null,
    constraint sg_icmp_rule_identity
        unique (ip_v, sg),
    constraint fk_sg_icmp_rule___sg
       foreign key(sg) references sgroups.tbl_sg(id)
            on delete cascade
            on update restrict
            deferrable initially deferred
);

drop table if exists sgroups.tbl_sg_sg_icmp_rule cascade;
create table sgroups.tbl_sg_sg_icmp_rule (
    id bigint generated always as identity primary key,
    ip_v sgroups.ip_family not null,
    types sgroups.icmp_types not null,
    sg_from bigint not null,
    sg_to bigint not null,
    logs boolean not null,
    trace boolean not null,
    constraint sg_sg_icmp_rule_identity
        unique (ip_v, sg_from, sg_to),
    constraint fk_sg_sg_icmp_rule___sg_from
       foreign key(sg_from) references sgroups.tbl_sg(id)
            on delete cascade
            on update restrict
               deferrable initially deferred,
    constraint fk_sg_sg_icmp_rule___sg_to
       foreign key(sg_to) references sgroups.tbl_sg(id)
            on delete cascade
            on update restrict
               deferrable initially deferred
);

drop view if exists sgroups.vu_sg_icmp_rule;
create or replace view sgroups.vu_sg_icmp_rule as (
    select ip_v,
           types,
           (select "name" from sgroups.tbl_sg where id = R.sg) as sg,
           logs,
           trace
      from sgroups.tbl_sg_icmp_rule as R
);

drop view if exists sgroups.vu_sg_sg_icmp_rule;
create or replace view sgroups.vu_sg_sg_icmp_rule as (
    select ip_v,
           types,
           (select "name" from sgroups.tbl_sg where id = R.sg_from) as sg_from,
           (select "name" from sgroups.tbl_sg where id = R.sg_to) as sg_to,
           logs,
           trace
      from sgroups.tbl_sg_sg_icmp_rule as R
);

--------------------------------------- READERS ---------------------------------------
drop function if exists sgroups.list_sg_icmp_rule(sgroups.cname[]) cascade ;
create or replace function sgroups.list_sg_icmp_rule(sg_names sgroups.cname[] default null)
returns table (  ip_v sgroups.ip_family,
                types sgroups.icmp_types,
                   sg sgroups.cname,
                 logs boolean,
                trace boolean
               )
as $$
begin
   return query select r.ip_v,
                       r.types,
                       r.sg,
                       r.logs,
                       r.trace
                  from sgroups.vu_sg_icmp_rule as r
                 where sg_names is null
                    or r.sg = any (sg_names);
end;
$$ language plpgsql immutable;

drop function if exists sgroups.list_sg_sg_icmp_rule (
                                   sgroups.cname[],
                                   sgroups.cname[]
                                ) cascade;
create or replace function sgroups.list_sg_sg_icmp_rule (
                                      sgFrom sgroups.cname[] default null,
                                      sgTo sgroups.cname[] default null
                                   )
returns table (   ip_v sgroups.ip_family,
                 types sgroups.icmp_types,
               sg_from sgroups.cname,
                 sg_to sgroups.cname,
                  logs boolean,
                 trace boolean
               )
as $$
begin
   return query select r.ip_v,
                       r.types,
                       r.sg_from,
                       r.sg_to,
                       r.logs,
                       r.trace
                  from sgroups.vu_sg_sg_icmp_rule as r
                 where ( sgFrom is null or
                         r.sg_from = any (sgFrom) )
                   and ( sgTo is null or
                         r.sg_to = any (sgTo) );
end;
$$ language plpgsql immutable;

--------------------------------------- WRITERS ---------------------------------------
drop type if exists sgroups.row_of__sg_icmp_rule cascade ;
create type sgroups.row_of__sg_icmp_rule as (
   ip_v sgroups.ip_family,
   sg sgroups.cname,
   types sgroups.icmp_types,
   logs boolean,
   trace boolean
);

drop function if exists sgroups.sync_sg_icmp_rule(sgroups.sync_op, sgroups.row_of__sg_icmp_rule) cascade;
create function sgroups.sync_sg_icmp_rule(op sgroups.sync_op, d sgroups.row_of__sg_icmp_rule)
returns bool
as $$
declare
    ret bigint;
    sg_id bigint;
begin
    select id from sgroups.tbl_sg where "name" = (d).sg into sg_id;
    if sg_id is null then
        raise exception 'related SG(%) is not exist', (d).sg;
    end if;
    if op = 'del' then
        delete from sgroups.tbl_sg_icmp_rule
         where ip_v = (d).ip_v
           and sg = sg_id
     returning id into ret;
    elsif op = 'upd' then
        update sgroups.tbl_sg_icmp_rule
           set types = (d).types,
               logs = (d).logs,
               trace = (d).trace
         where ip_v = (d).ip_v
           and sg = sg_id
     returning id into ret;
    elsif op = 'ups' then
        insert into sgroups.tbl_sg_icmp_rule(ip_v, sg, types, logs, trace)
                    values ((d).ip_v, sg_id, (d).types, (d).logs, (d).trace)
            on conflict
               on constraint sg_icmp_rule_identity
                  do update
                        set types = (d).types,
                            logs = (d).logs,
                            trace = (d).trace
     returning id into ret;
    elsif op = 'ins' then
        insert into sgroups.tbl_sg_icmp_rule(ip_v, sg, types, logs, trace)
                    values ((d).ip_v, sg_id, (d).types, (d).logs, (d).trace)
            on conflict
               on constraint sg_icmp_rule_identity
                  do nothing
     returning id into ret;
    end if;
    return ret is not null;
end;
$$ language plpgsql strict;


drop type if exists sgroups.row_of__sg_sg_icmp_rule cascade;
create type sgroups.row_of__sg_sg_icmp_rule as (
    ip_v sgroups.ip_family,
    sg_from sgroups.cname,
    sg_to sgroups.cname,
    types sgroups.icmp_types,
    logs boolean,
    trace boolean
);

drop function if exists sgroups.sync_sg_sg_icmp_rule(sgroups.sync_op, sgroups.row_of__sg_sg_icmp_rule) cascade;
create function sgroups.sync_sg_sg_icmp_rule(op sgroups.sync_op, d sgroups.row_of__sg_sg_icmp_rule)
returns bool
as $$
declare
    ret bigint;
    sg_from_id bigint;
    sg_to_id bigint;
begin
    select id from sgroups.tbl_sg where "name" = (d).sg_from into sg_from_id;
    if sg_from_id is null then
        raise exception 'related SG as sg-from(%) is not exist', (d).sg_from;
    end if;
    select id from sgroups.tbl_sg where "name" = (d).sg_to into sg_to_id;
    if sg_to_id is null then
        raise exception 'related SG as sg-to(%) is not exist', (d).sg_to;
    end if;
    if op = 'del' then
        delete from sgroups.tbl_sg_sg_icmp_rule
         where ip_v = (d).ip_v
           and sg_from = sg_from_id
           and sg_to = sg_to_id
     returning id into ret;
    elsif op = 'upd' then
        update sgroups.tbl_sg_sg_icmp_rule
           set types = (d).types,
               logs = (d).logs,
               trace = (d).trace
         where ip_v = (d).ip_v
           and sg_from = sg_from_id
           and sg_to = sg_to_id
     returning id into ret;
    elsif op = 'ups' then
        insert into sgroups.tbl_sg_sg_icmp_rule(ip_v, sg_from, sg_to, types, logs, trace)
                    values ((d).ip_v, sg_from_id, sg_to_id, (d).types, (d).logs, (d).trace)
            on conflict
               on constraint sg_sg_icmp_rule_identity
                   do update
                         set types = (d).types,
                             logs = (d).logs,
                             trace = (d).trace
     returning id into ret;
    elsif op = 'ins' then
        insert into sgroups.tbl_sg_sg_icmp_rule(ip_v, sg_from, sg_to, types, logs, trace)
                    values ((d).ip_v, sg_from_id, sg_to_id, (d).types, (d).logs, (d).trace)
            on conflict
               on constraint sg_sg_icmp_rule_identity
                  do nothing
     returning id into ret;
    end if;
    return ret is not null;
end;
$$ language plpgsql strict;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT no-down-scenarion;
-- +goose StatementEnd
