-- +goose Up
-- +goose StatementBegin
------------------------------- types ---------------------------
drop type if exists sgroups.rule_action cascade;
create type sgroups.rule_action as enum (
    'DROP',
    'ACCEPT'
);

-- ie_sg_sg_rule
alter table sgroups.tbl_ie_sg_sg_rule
        add column action sgroups.rule_action not null default 'ACCEPT'::sgroups.rule_action,
        add column priority smallint;

create or replace view sgroups.vu_ie_sg_sg_rule as
select proto,
       (select "name" from sgroups.tbl_sg where id = R.sg_local) as sg_local,
       (select "name" from sgroups.tbl_sg where id = R.sg) as sg,
       traffic,
       ports,
       logs,
       trace,
       action,
       priority
  from sgroups.tbl_ie_sg_sg_rule as R;

drop function if exists sgroups.list_ie_sg_sg_rules(sgroups.cname[], sgroups.cname[]) cascade;
create or replace function sgroups.list_ie_sg_sg_rules (
    sglocals sgroups.cname[] default null,
    sgs sgroups.cname[] default null
) returns table ( proto sgroups.proto,
                  sg_local sgroups.cname,
                  sg sgroups.cname,
                  traffic sgroups.traffic,
                  ports sgroups.sg_rule_ports[],
                  logs bool,
                  trace bool,
                  action sgroups.rule_action,
                  priority smallint
                )
as $$
begin
    return query select r.proto,
                        r.sg_local,
                        r.sg,
                        r.traffic,
                        r.ports,
                        r.logs,
                        r.trace,
                        r.action,
                        r.priority
                   from sgroups.vu_ie_sg_sg_rule as r
                  where ( sglocals is null or r.sg_local = any(sglocals) )
                    and ( sgs is null or r.sg = any(sgs) );
end;
$$ language plpgsql immutable;

alter type sgroups.row_of__ie_sg_sg_rule
      add attribute action sgroups.rule_action,
      add attribute priority smallint;

drop function if exists sgroups.sync_ie_sg_sg_rule(sgroups.sync_op, sgroups.row_of__ie_sg_sg_rule);
create function sgroups.sync_ie_sg_sg_rule(op sgroups.sync_op, d sgroups.row_of__ie_sg_sg_rule)
    returns boolean
as $$
declare
    ret bigint;
    sgLocalID bigint;
    sgID bigint;
begin
    select id from sgroups.tbl_sg where "name" = (d).sg_local into sgLocalID;
    if sgLocalID is null then
        raise exception 'on check SgLocal it found the SG(%) not exists', (d).sg_local;
    end if;
    select id from sgroups.tbl_sg where "name" = (d).sg into sgID;
    if sgID is null then
        raise exception 'on check Sg it found the SG(%) not exists', (d).sg;
    end if;
    if op = 'del' then
        delete from sgroups.tbl_ie_sg_sg_rule
         where proto = (d).proto
           and sg_local = sgLocalID
           and sg = sgID
           and traffic = (d).traffic
     returning id into ret;
    elseif op = 'upd' then
        update sgroups.tbl_ie_sg_sg_rule
           set ports = (d).ports,
               logs = (d).logs,
               trace = (d).trace,
               action = (d).action,
               priority = (d).priority
         where proto = (d).proto
           and sg_local = sgLocalID
           and sg = sgID
           and traffic = (d).traffic
     returning id into ret;
    elseif op = 'ups' then
        insert into sgroups.tbl_ie_sg_sg_rule (proto, sg_local, sg, traffic, ports, logs, trace, action, priority)
             values ((d).proto, sgLocalID, sgID, (d).traffic, (d).ports, (d).logs, (d).trace, (d).action, (d).priority)
            on conflict
               on constraint ie_sg_sg_rule_identity
                  do update
                     set ports = (d).ports,
                         logs = (d).logs,
                         trace = (d).trace,
                         action = (d).action,
                         priority = (d).priority
     returning id into ret;
    elseif op = 'ins' then
        insert into sgroups.tbl_ie_sg_sg_rule (proto, sg_local, sg, traffic, ports, logs, trace, action, priority)
             values ((d).proto, sgLocalID, sgID, (d).traffic, (d).ports, (d).logs, (d).trace, (d).action, (d).priority)
            on conflict
               on constraint ie_sg_sg_rule_identity
                  do nothing
     returning id into ret;
    end if;
    return ret is not null;
end;
$$ language plpgsql strict;

-- ie_sg_sg_icmp_rule
alter table sgroups.tbl_ie_sg_sg_icmp_rule
        add column action sgroups.rule_action not null default 'ACCEPT'::sgroups.rule_action,
        add column priority smallint;

create or replace view sgroups.vu_ie_sg_sg_icmp_rule as
select ip_v,
       types,
       (select "name" from sgroups.tbl_sg where id = R.sg_local) as sg_local,
       (select "name" from sgroups.tbl_sg where id = R.sg) as sg,
       traffic,
       logs,
       trace,
       action,
       priority
  from sgroups.tbl_ie_sg_sg_icmp_rule as R;

drop function if exists sgroups.list_ie_sg_sg_icmp_rules(sgroups.cname[], sgroups.cname[]) cascade;
create or replace function sgroups.list_ie_sg_sg_icmp_rules (
    sglocals sgroups.cname[] default null,
    sgs sgroups.cname[] default null
) returns table ( ip_v sgroups.ip_family,
                  types sgroups.icmp_types,
                  sg_local sgroups.cname,
                  sg sgroups.cname,
                  traffic sgroups.traffic,
                  logs bool,
                  trace bool,
                  action sgroups.rule_action,
                  priority smallint
                )
as $$
begin
    return query select r.ip_v,
                        r.types,
                        r.sg_local,
                        r.sg,
                        r.traffic,
                        r.logs,
                        r.trace,
                        r.action,
                        r.priority
                   from sgroups.vu_ie_sg_sg_icmp_rule as r
                  where ( sglocals is null or r.sg_local = any(sglocals) )
                    and ( sgs is null or r.sg = any(sgs) );
end;
$$ language plpgsql immutable;

alter type sgroups.row_of__ie_sg_sg_icmp_rule
      add attribute action sgroups.rule_action,
      add attribute priority smallint;

drop function if exists sgroups.sync_ie_sg_sg_icmp_rule(op sgroups.sync_op, d sgroups.row_of__ie_sg_sg_icmp_rule) cascade;
create function sgroups.sync_ie_sg_sg_icmp_rule(op sgroups.sync_op, d sgroups.row_of__ie_sg_sg_icmp_rule)
    returns boolean
as $$
declare
    ret bigint;
    sgLocalID bigint;
    sgID bigint;
begin
    select id from sgroups.tbl_sg where "name" = (d).sg_local into sgLocalID;
    if sgLocalID is null then
        raise exception 'on check SgLocal it found the SG(%) not exists', (d).sg_local;
    end if;
    select id from sgroups.tbl_sg where "name" = (d).sg into sgID;
    if sgID is null then
        raise exception 'on check Sg it found the SG(%) not exists', (d).sg;
    end if;
    if op = 'del' then
        delete from sgroups.tbl_ie_sg_sg_icmp_rule
         where ip_v = (d).ip_v
           and sg_local = sgLocalID
           and sg = sgID
           and traffic = (d).traffic
     returning id into ret;
    elseif op = 'upd' then
        update sgroups.tbl_ie_sg_sg_icmp_rule
           set types = (d).types,
               logs  = (d).logs,
               trace = (d).trace,
               action = (d).action,
               priority = (d).priority
         where ip_v = (d).ip_v
           and sg_local = sgLocalID
           and sg = sgID
           and traffic = (d).traffic
     returning id into ret;
    elseif op = 'ups' then
        insert into sgroups.tbl_ie_sg_sg_icmp_rule (ip_v, types, sg_local, sg, traffic, logs, trace, action, priority)
             values ((d).ip_v, (d).types, sgLocalID, sgID, (d).traffic, (d).logs, (d).trace, (d).action, (d).priority)
            on conflict
               on constraint ie_sg_sg_icmp_rule_identity
                  do update
                     set types = (d).types,
                         logs  = (d).logs,
                         trace = (d).trace,
                         action = (d).action,
                         priority = (d).priority
     returning id into ret;
    elseif op = 'ins' then
        insert into sgroups.tbl_ie_sg_sg_icmp_rule (ip_v, types, sg_local, sg, traffic, logs, trace, action, priority)
             values ((d).ip_v, (d).types, sgLocalID, sgID, (d).traffic, (d).logs, (d).trace, (d).action, (d).priority)
            on conflict
                on constraint ie_sg_sg_icmp_rule_identity
                    do nothing
     returning id into ret;
    end if;
    return ret is not null;
end;
$$ language plpgsql strict;

-- cidr_sg_rule
alter table sgroups.tbl_cidr_sg_rule
        add column action sgroups.rule_action not null default 'ACCEPT'::sgroups.rule_action,
        add column priority smallint;

create or replace view sgroups.vu_cidr_sg_rule as
select proto,
       cidr,
       (select "name" from sgroups.tbl_sg where id = R.sg) as sg,
       traffic,
       ports,
       logs,
       trace,
       action,
       priority
  from sgroups.tbl_cidr_sg_rule as R;

drop function if exists sgroups.list_cidr_sg_rule(sgroups.cname[]) cascade;
create or replace function sgroups.list_cidr_sg_rule (
    sgs sgroups.cname[] default null
) returns table ( proto sgroups.proto,
                  cidr cidr,
                  sg sgroups.cname,
                  traffic sgroups.traffic,
                  ports sgroups.sg_rule_ports[],
                  logs bool,
                  trace bool,
                  action sgroups.rule_action,
                  priority smallint
                )
as $$
begin
    return query select r.proto,
                        r.cidr,
                        r.sg,
                        r.traffic,
                        r.ports,
                        r.logs,
                        r.trace,
                        r.action,
                        r.priority
                   from sgroups.vu_cidr_sg_rule as r
                  where ( sgs is null or
                          r.sg = any(sgs) );
end;
$$ language plpgsql immutable;

alter type sgroups.row_of__cidr_sg_rule
      add attribute action sgroups.rule_action,
      add attribute priority smallint;

drop function if exists sgroups.sync_cidr_sg_rule(sgroups.sync_op, sgroups.row_of__cidr_sg_rule);
create function sgroups.sync_cidr_sg_rule(op sgroups.sync_op, d sgroups.row_of__cidr_sg_rule)
    returns boolean
as $$
declare
    ret bigint;
    sgID bigint;
begin
    select id from sgroups.tbl_sg where "name" = (d).sg into sgID;
    if sgID is null then
        raise exception 'on check SG it found the SG(%) not exist', (d).sg;
    end if;
    if op = 'del' then
        delete from sgroups.tbl_cidr_sg_rule
         where proto = (d).proto
           and cidr = (d).cidr
           and sg = sgID
           and traffic = (d).traffic
     returning id into ret;
    elsif op = 'upd' then
        update sgroups.tbl_cidr_sg_rule
           set ports = (d).ports,
               logs = (d).logs,
               trace = (d).trace,
               action = (d).action,
               priority = (d).priority
         where proto = (d).proto
           and cidr = (d).cidr
           and sg = sgID
           and traffic = (d).traffic
     returning id into ret;
    elsif op = 'ups' then
        insert into sgroups.tbl_cidr_sg_rule (proto, cidr, sg, traffic, ports, logs, trace, action, priority)
             values ((d).proto, (d).cidr, sgID, (d).traffic ,(d).ports, (d).logs, (d).trace, (d).action, (d).priority)
            on conflict
               on constraint cidr_sg_rule_identity
                  do update
                     set ports = (d).ports,
                         logs = (d).logs,
                         trace = (d).trace,
                         action = (d).action,
                         priority = (d).priority
      returning id into ret;
    elsif op = 'ins' then
        insert into sgroups.tbl_cidr_sg_rule (proto, cidr, sg, traffic, ports, logs, trace, action, priority)
             values ((d).proto, (d).cidr, sgID, (d).traffic ,(d).ports, (d).logs, (d).trace, (d).action, (d).priority)
            on conflict
               on constraint cidr_sg_rule_identity
                  do nothing
     returning id into ret;
    end if;
    return ret is not null;
end;
$$ language plpgsql strict;

-- cidr_sg_icmp_rule
alter table sgroups.tbl_cidr_sg_icmp_rule
        add column action sgroups.rule_action not null default 'ACCEPT'::sgroups.rule_action,
        add column priority smallint;

create or replace view sgroups.vu_cidr_sg_icmp_rule as
select ip_v,
       types,
       cidr,
       (select "name" from sgroups.tbl_sg where id = R.sg) as sg,
       traffic,
       logs,
       trace,
       action,
       priority
  from sgroups.tbl_cidr_sg_icmp_rule as R;

drop function if exists sgroups.list_cidr_sg_icmp_rules(sgroups.cname[]) cascade;
create or replace function sgroups.list_cidr_sg_icmp_rules (
    sgs sgroups.cname[] default null
) returns table ( ip_v sgroups.ip_family,
                  types sgroups.icmp_types,
                  cidr cidr,
                  sg sgroups.cname,
                  traffic sgroups.traffic,
                  logs bool,
                  trace bool,
                  action sgroups.rule_action,
                  priority smallint
                )
as $$
begin
    return query select r.ip_v,
                        r.types,
                        r.cidr,
                        r.sg,
                        r.traffic,
                        r.logs,
                        r.trace,
                        r.action,
                        r.priority
                   from sgroups.vu_cidr_sg_icmp_rule as r
                  where ( sgs is null or r.sg = any(sgs) );
end;
$$ language plpgsql immutable;

alter type sgroups.row_of__cidr_sg_icmp_rule
    add attribute action sgroups.rule_action,
    add attribute priority smallint;

drop function if exists sgroups.sync_cidr_sg_icmp_rule(op sgroups.sync_op, d sgroups.row_of__cidr_sg_icmp_rule) cascade;
create function sgroups.sync_cidr_sg_icmp_rule(op sgroups.sync_op, d sgroups.row_of__cidr_sg_icmp_rule)
    returns boolean
as $$
declare
    ret bigint;
    sgID bigint;
begin
    select id from sgroups.tbl_sg where "name" = (d).sg into sgID;
    if sgID is null then
        raise exception 'on check SG it found the SG(%) not exists', (d).sg;
    end if;
    if op = 'del' then
        delete from sgroups.tbl_cidr_sg_icmp_rule
         where ip_v = (d).ip_v
           and cidr = (d).cidr
           and sg = sgID
           and traffic = (d).traffic
     returning id into ret;
    elseif op = 'upd' then
        update sgroups.tbl_cidr_sg_icmp_rule
           set types = (d).types,
               logs  = (d).logs,
               trace = (d).trace,
               action = (d).action,
               priority = (d).priority
         where ip_v = (d).ip_v
           and cidr = (d).cidr
           and sg = sgID
           and traffic = (d).traffic
     returning id into ret;
    elseif op = 'ups' then
        insert into sgroups.tbl_cidr_sg_icmp_rule (ip_v, types, cidr, sg, traffic, logs, trace, action, priority)
             values ((d).ip_v, (d).types, (d).cidr, sgID, (d).traffic, (d).logs, (d).trace, (d).action, (d).priority)
            on conflict
               on constraint cidr_sg_icmp_rule_identity
                  do update
                     set types = (d).types,
                         logs  = (d).logs,
                          trace = (d).trace,
                          action = (d).action,
                          priority = (d).priority
     returning id into ret;
    elseif op = 'ins' then
        insert into sgroups.tbl_cidr_sg_icmp_rule (ip_v, types, cidr, sg, traffic, logs, trace, action, priority)
             values ((d).ip_v, (d).types, (d).cidr, sgID, (d).traffic, (d).logs, (d).trace, (d).action, (d).priority)
            on conflict
               on constraint cidr_sg_icmp_rule_identity
                  do nothing
     returning id into ret;
    end if;
    return ret is not null;
end;
$$ language plpgsql strict;

-- fqdn_rule
alter table sgroups.tbl_fqdn_rule
        add column action sgroups.rule_action not null default 'ACCEPT'::sgroups.rule_action,
        add column priority smallint;

create or replace view sgroups.vu_fqdn_rule as
select (select "name" from sgroups.tbl_sg where id = R.sg_from) as sg_from,
       fqdn_to,
       proto,
       ports,
       logs,
       ndpi_protocols,
       action,
       priority
  from sgroups.tbl_fqdn_rule as R;

drop function if exists sgroups.list_fqdn_rule(sgroups.cname[]) cascade;
create or replace function sgroups.list_fqdn_rule (
    sgfrom sgroups.cname[] default null
) returns table (
                    sg_from sgroups.cname,
                    fqdn_to sgroups.fqdn,
                    proto sgroups.proto,
                    ports sgroups.sg_rule_ports[],
                    logs bool,
                    ndpi_protocols citext[],
                    action sgroups.rule_action,
                    priority smallint
                )
as $$
begin
    return query select r.sg_from,
                        r.fqdn_to,
                        r.proto,
                        r.ports,
                        r.logs,
                        r.ndpi_protocols,
                        r.action,
                        r.priority
                   from sgroups.vu_fqdn_rule as r
                  where ( sgfrom is null or
                          r.sg_from = any (sgfrom) );
end;
$$ language plpgsql immutable;

alter type sgroups.row_of__fqdn_rule
      add attribute action sgroups.rule_action,
      add attribute priority smallint;

drop function if exists sgroups.sync_fqdn_rule(op sgroups.sync_op, d sgroups.row_of__fqdn_rule) cascade;
create function sgroups.sync_fqdn_rule(op sgroups.sync_op, d sgroups.row_of__fqdn_rule)
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
               logs = (d).logs,
               ndpi_protocols = (d).ndpi_protocols,
               action = (d).action,
               priority = (d).priority
         where sg_from = sgFrom
           and fqdn_to = (d).fqdn_to
           and proto = (d).proto
     returning id into ret;
    elseif op = 'ups' then
        insert into sgroups.tbl_fqdn_rule (sg_from, fqdn_to, proto, ports, logs, ndpi_protocols, action, priority)
             values (sgFrom, (d).fqdn_to, (d).proto, (d).ports, (d).logs, (d).ndpi_protocols, (d).action, (d).priority)
           on conflict
              on constraint sg_fqdn_rule_identity
                 do update
                    set ports = (d).ports,
                        logs = (d).logs,
                        ndpi_protocols = (d).ndpi_protocols,
                        action = (d).action,
                        priority = (d).priority
     returning id into ret;
    elseif op = 'ins' then
        insert into sgroups.tbl_fqdn_rule (sg_from, fqdn_to, proto, ports, logs, ndpi_protocols, action, priority)
             values (sgFrom, (d).fqdn_to, (d).proto, (d).ports, (d).logs, (d).ndpi_protocols, (d).action, (d).priority)
            on conflict
               on constraint sg_fqdn_rule_identity
                  do nothing
        returning id into ret;
    end if;
    return ret is not null;
end;
$$ language plpgsql strict;

-- sg_icmp_rule
alter table sgroups.tbl_sg_icmp_rule
        add column action sgroups.rule_action not null default 'ACCEPT'::sgroups.rule_action;

create or replace view sgroups.vu_sg_icmp_rule as
select ip_v,
       types,
       (select "name" from sgroups.tbl_sg where id = R.sg) as sg,
       logs,
       trace,
       action
  from sgroups.tbl_sg_icmp_rule as R;

drop function if exists sgroups.list_sg_icmp_rule(sgroups.cname[]) cascade;
create or replace function sgroups.list_sg_icmp_rule (
    sg_names sgroups.cname[] default null
) returns table (  ip_v sgroups.ip_family,
                   types sgroups.icmp_types,
                   sg sgroups.cname,
                   logs boolean,
                   trace boolean,
                   action sgroups.rule_action
                )
as $$
begin
    return query select r.ip_v,
                        r.types,
                        r.sg,
                        r.logs,
                        r.trace,
                        r.action
                   from sgroups.vu_sg_icmp_rule as r
                  where sg_names is null
                     or r.sg = any (sg_names);
end;
$$ language plpgsql immutable;

alter type sgroups.row_of__sg_icmp_rule
      add attribute action sgroups.rule_action;

drop function if exists sgroups.sync_sg_icmp_rule(sgroups.sync_op, sgroups.row_of__sg_icmp_rule) cascade;
create function sgroups.sync_sg_icmp_rule(op sgroups.sync_op, d sgroups.row_of__sg_icmp_rule)
    returns boolean
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
               trace = (d).trace,
               action = (d).action
         where ip_v = (d).ip_v
           and sg = sg_id
     returning id into ret;
    elsif op = 'ups' then
        insert into sgroups.tbl_sg_icmp_rule(ip_v, sg, types, logs, trace, action)
             values ((d).ip_v, sg_id, (d).types, (d).logs, (d).trace, (d).action)
            on conflict
               on constraint sg_icmp_rule_identity
                  do update
                     set types = (d).types,
                         logs = (d).logs,
                         trace = (d).trace,
                         action = (d).action
     returning id into ret;
    elsif op = 'ins' then
        insert into sgroups.tbl_sg_icmp_rule(ip_v, sg, types, logs, trace, action)
             values ((d).ip_v, sg_id, (d).types, (d).logs, (d).trace, (d).action)
            on conflict
               on constraint sg_icmp_rule_identity
                  do nothing
     returning id into ret;
    end if;
    return ret is not null;
end;
$$ language plpgsql strict;

-- sg_rule
alter table sgroups.tbl_sg_rule
        add column action sgroups.rule_action not null default 'ACCEPT'::sgroups.rule_action,
        add column priority smallint;

create or replace view sgroups.vu_sg_rule as
select (select "name" from sgroups.tbl_sg where id = R.sg_from) as sg_from,
       (select "name" from sgroups.tbl_sg where id = R.sg_to) as sg_to,
       proto,
       ports,
       logs,
       action,
       priority
  from sgroups.tbl_sg_rule as R;

drop function if exists sgroups.list_sg_rule(sgroups.cname[], sgroups.cname[]) cascade;
create or replace function sgroups.list_sg_rule(
    sgfrom sgroups.cname[] default null,
    sgto sgroups.cname[] default null
) returns table ( sg_from sgroups.cname,
                  sg_to sgroups.cname,
                  proto sgroups.proto,
                  ports sgroups.sg_rule_ports[],
                  logs bool,
                  action sgroups.rule_action,
                  priority smallint
                )
as $$
begin
    return query select r.sg_from,
                        r.sg_to,
                        r.proto,
                        r.ports,
                        r.logs,
                        r.action,
                        r.priority
                   from sgroups.vu_sg_rule as r
                  where ( sgfrom is null or
                          r.sg_from = any (sgfrom) )
                    and ( sgto is null or
                          r.sg_to = any (sgto) );
end;
$$ language plpgsql immutable;

alter type sgroups.row_of__sg_rule
      add attribute action sgroups.rule_action,
      add attribute priority smallint;

drop function if exists sgroups.sync_sg_rule(sgroups.sync_op, sgroups.row_of__sg_rule) cascade;
create function sgroups.sync_sg_rule(op sgroups.sync_op, d sgroups.row_of__sg_rule)
    returns boolean
as $$
declare
    ret bigint;
    sgFrom bigint;
    sgTo bigint;
begin
    select id from sgroups.tbl_sg where "name" = (d).sg_from into sgFrom;
    if sgFrom is null then
        raise exception 'on check SG-From it found the SG(%) not exist', (d).sg_from;
    end if;
    select id from sgroups.tbl_sg where "name" = (d).sg_to into sgTo;
    if sgTo is null then
        raise exception 'on check SG-To it found the SG(%) not exist', (d).sg_to;
    end if;
    if op = 'del' then
        delete from sgroups.tbl_sg_rule
         where sg_from = sgFrom
           and sg_to = sgTo
           and proto = (d).proto
     returning id into ret;
    elsif op = 'upd' then
        update sgroups.tbl_sg_rule
           set ports = (d).ports,
               logs = (d).logs,
               action = (d).action,
               priority = (d).priority
         where sg_from = sgFrom
           and sg_to = sgTo
           and proto = (d).proto
     returning id into ret;
    elsif op = 'ups' then
        insert into sgroups.tbl_sg_rule (sg_from, sg_to, proto, ports, logs, action, priority)
             values (sgFrom, sgTo, (d).proto, (d).ports, (d).logs, (d).action, (d).priority)
            on conflict
               on constraint sg_rule_identity
                  do update
                     set ports = (d).ports,
                         logs = (d).logs,
                         action = (d).action,
                         priority = (d).priority
     returning id into ret;
    elsif op = 'ins' then
        insert into sgroups.tbl_sg_rule (sg_from, sg_to, proto, ports, logs, action, priority)
             values (sgFrom, sgTo, (d).proto, (d).ports, (d).logs, (d).action, (d).priority)
            on conflict
               on constraint sg_rule_identity
                  do nothing
     returning id into ret;
    end if;
    return ret is not null;
end;
$$ language plpgsql strict;

-- sg_sg_icmp_rule
alter table sgroups.tbl_sg_sg_icmp_rule
        add column action sgroups.rule_action not null default 'ACCEPT'::sgroups.rule_action,
        add column priority smallint;

create or replace view sgroups.vu_sg_sg_icmp_rule as
select ip_v,
       types,
       (select "name" from sgroups.tbl_sg where id = R.sg_from) as sg_from,
       (select "name" from sgroups.tbl_sg where id = R.sg_to) as sg_to,
       logs,
       trace,
       action,
       priority
  from sgroups.tbl_sg_sg_icmp_rule as R;

drop function if exists sgroups.list_sg_sg_icmp_rule(sgroups.cname[], sgroups.cname[]) cascade;
create or replace function sgroups.list_sg_sg_icmp_rule(
    sgFrom sgroups.cname[] default null,
    sgTo sgroups.cname[] default null
) returns table (   ip_v sgroups.ip_family,
                    types sgroups.icmp_types,
                    sg_from sgroups.cname,
                    sg_to sgroups.cname,
                    logs boolean,
                    trace boolean,
                    action sgroups.rule_action,
                    priority smallint
                )
as $$
begin
    return query select r.ip_v,
                        r.types,
                        r.sg_from,
                        r.sg_to,
                        r.logs,
                        r.trace,
                        r.action,
                        r.priority
                   from sgroups.vu_sg_sg_icmp_rule as r
                  where ( sgFrom is null or
                          r.sg_from = any (sgFrom) )
                    and ( sgTo is null or
                          r.sg_to = any (sgTo) );
end;
$$ language plpgsql immutable;

alter type sgroups.row_of__sg_sg_icmp_rule
      add attribute action sgroups.rule_action,
      add attribute priority smallint;

drop function if exists sgroups.sync_sg_sg_icmp_rule(sgroups.sync_op, sgroups.row_of__sg_sg_icmp_rule) cascade;
create function sgroups.sync_sg_sg_icmp_rule(op sgroups.sync_op, d sgroups.row_of__sg_sg_icmp_rule)
    returns boolean
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
               trace = (d).trace,
               action = (d).action,
               priority = (d).priority
         where ip_v = (d).ip_v
           and sg_from = sg_from_id
           and sg_to = sg_to_id
     returning id into ret;
    elsif op = 'ups' then
        insert into sgroups.tbl_sg_sg_icmp_rule(ip_v, sg_from, sg_to, types, logs, trace, action, priority)
             values ((d).ip_v, sg_from_id, sg_to_id, (d).types, (d).logs, (d).trace, (d).action, (d).priority)
            on conflict
               on constraint sg_sg_icmp_rule_identity
                  do update
                     set types = (d).types,
                         logs = (d).logs,
                         trace = (d).trace,
                         action = (d).action,
                         priority = (d).priority
     returning id into ret;
    elsif op = 'ins' then
        insert into sgroups.tbl_sg_sg_icmp_rule(ip_v, sg_from, sg_to, types, logs, trace, action, priority)
             values ((d).ip_v, sg_from_id, sg_to_id, (d).types, (d).logs, (d).trace, (d).action, (d).priority)
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
