-- +goose Up
-- +goose StatementBegin
create extension if not exists citext;

--------------------------------------- TYPES ---------------------------------------
drop domain if exists sgroups.fqdn cascade;

create domain sgroups.fqdn
           as citext
   constraint fqdn_pattern
        check (
           value ~ '^([a-z0-9\*][a-z0-9_-]{1,62}){1}(\.[a-z0-9_][a-z0-9_-]{0,62})*$'
        )
   constraint fqdn_length
        check (
           length(value) < 256
        );

--------------------------------------- TABLES ---------------------------------------
drop table if exists sgroups.tbl_fqdn_rule cascade;
create table sgroups.tbl_fqdn_rule (
    id bigint generated always as identity primary key,
    sg_from bigint not null,
    fqdn_to sgroups.fqdn not null,
    proto sgroups.proto not null,
    ports sgroups.sg_rule_ports[],
    logs bool not null default false,
    constraint sg_fqdn_rule_identity
        unique (sg_from, fqdn_to, proto),
    constraint "S_ports_dont_intersect"
         check (
            sgroups.s_ports_dont_intersect(ports)
         ),
    constraint fk_fqdn_rule___sg_from
       foreign key(sg_from) references sgroups.tbl_sg(id)
            on delete cascade
            on update restrict
               deferrable initially deferred
);
comment on table sgroups.tbl_fqdn_rule
    is 'SG-to-FQDN rule represents firewall acceptance rule';
comment on column sgroups.tbl_fqdn_rule.sg_from is 'SG-from is net packet source';
comment on column sgroups.tbl_fqdn_rule.fqdn_to is 'FQDN-to is net packet destination';
comment on column sgroups.tbl_fqdn_rule.proto is 'proto is network transport protocol';
comment on constraint sg_fqdn_rule_identity on sgroups.tbl_fqdn_rule
     is 'SG-to-FQDN identity(SG-From, FQDN-To, proto) is unique key to firewall rule';
comment on column sgroups.tbl_fqdn_rule.ports
     is 'ports is variety of Source and Destination ports multi ranges';
comment on column sgroups.tbl_fqdn_rule.logs
     is 'switch logs ON|OFF';
comment on constraint "S_ports_dont_intersect" on sgroups.tbl_fqdn_rule
     is 'checks and prevents any Source ports intersections';
comment on constraint fk_fqdn_rule___sg_from on sgroups.tbl_fqdn_rule
     is 'reference to source SG';


create or replace view sgroups.vu_fqdn_rule as
select (select "name" from sgroups.tbl_sg where id = R.sg_from) as sg_from,
       fqdn_to,
       proto,
       ports,
       logs
  from sgroups.tbl_fqdn_rule as R;

--------------------------------------- WRITERS ---------------------------------------
drop type if exists sgroups.row_of__fqdn_rule cascade ;
create type sgroups.row_of__fqdn_rule as (
    sg_from sgroups.cname,
    fqdn_to sgroups.fqdn,
    proto sgroups.proto,
    ports sgroups.sg_rule_ports[],
    logs bool
);

drop function if exists sgroups.sync_fqdn_rule(sgroups.sync_op, sgroups.row_of__fqdn_rule);
create or replace function sgroups.sync_fqdn_rule(op sgroups.sync_op, d sgroups.row_of__fqdn_rule)
returns boolean
as $$
declare
   ret bigint;
   sgFrom bigint;
begin
   select id from sgroups.tbl_sg where "name" = (d).sg_from into sgFrom;
   if sgFrom is null then
      raise exception 'on check SG-From it found the SG(%) not exist', (d).sg_from;
   end if;
   if op = 'del' then
       delete from sgroups.tbl_fqdn_rule
        where sg_from = sgFrom
          and fqdn_to = (d).fqdn_to
          and proto = (d).proto
    returning id into ret;
   elseif op = 'upd' then
       update sgroups.tbl_fqdn_rule
          set ports = (d).ports,
              logs = (d).logs
        where sg_from = sgFrom
          and fqdn_to = (d).fqdn_to
          and proto = (d).proto
    returning id into ret;
   elseif op = 'ups' then
       insert into sgroups.tbl_fqdn_rule (sg_from, fqdn_to, proto, ports, logs)
       values (sgFrom, (d).fqdn_to, (d).proto, (d).ports, (d).logs)
           on conflict
              on constraint sg_fqdn_rule_identity
                 do update
                    set ports = (d).ports,
                        logs = (d).logs
    returning id into ret;
   elseif op = 'ins' then
       insert into sgroups.tbl_fqdn_rule (sg_from, fqdn_to, proto, ports, logs)
       values (sgFrom, (d).fqdn_to, (d).proto, (d).ports, (d).logs)
           on conflict
              on constraint sg_fqdn_rule_identity
                 do nothing
    returning id into ret;
   end if;
   return ret is not null;
end;
$$ language plpgsql strict;

--------------------------------------- READERS ---------------------------------------
drop function if exists sgroups.list_fqdn_rule(sgroups.cname[]) cascade;
create or replace function sgroups.list_fqdn_rule (
   sgfrom sgroups.cname[] default null
) returns table (
             sg_from sgroups.cname,
             fqdn_to sgroups.fqdn,
             proto sgroups.proto,
             ports sgroups.sg_rule_ports[],
             logs bool
          )
as $$
begin
   return query select r.sg_from,
                       r.fqdn_to,
                       r.proto,
                       r.ports,
                       r.logs
                  from sgroups.vu_fqdn_rule as r
                 where ( sgfrom is null or
                         r.sg_from = any (sgfrom) );
end;
$$ language plpgsql immutable;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT no-down-scenarion;
-- +goose StatementEnd
