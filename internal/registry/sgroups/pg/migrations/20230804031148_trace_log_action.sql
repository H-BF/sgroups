-- +goose Up
-- +goose StatementBegin
------------------------------- types ---------------------------
drop type if exists sgroups.chain_default_action cascade;
create type sgroups.chain_default_action as enum (
    'DROP',
    'ACCEPT'
);
------------------------------- tables ---------------------------
alter table sgroups.tbl_sg
        add column logs bool not null default false;
comment on column sgroups.tbl_sg.logs
     is 'switch logs ON|OFF';

alter table sgroups.tbl_sg
        add column trace bool not null default false;
comment on column sgroups.tbl_sg.trace
     is 'switch nf-trace ON|OFF';

alter table sgroups.tbl_sg
        add column default_action sgroups.chain_default_action
                   not null default 'DROP';
comment on column sgroups.tbl_sg.default_action
     is 'represents default chain action DROP|ACCEPT';

create or replace view sgroups.vu_sg as
select sg."name",
       nws.networks,
       sg.logs,
       sg.trace,
       sg.default_action
  from sgroups.tbl_sg as sg
  join lateral (
         select array_agg(nw."name") as networks
           from sgroups.tbl_network as nw
          where nw.sg = sg.id
       ) nws on true;

alter table sgroups.tbl_sg_rule
        add column logs bool not null default false;
comment on column sgroups.tbl_sg_rule.logs
     is 'switch logs ON|OFF';

create or replace view sgroups.vu_sg_rule as
select (select "name" from sgroups.tbl_sg where id = R.sg_from) as sg_from,
       (select "name" from sgroups.tbl_sg where id = R.sg_to) as sg_to,
       proto,
       ports,
       logs
  from sgroups.tbl_sg_rule as R;

------------------------------- readers ---------------------------

drop function sgroups.list_sg(names sgroups.cname[]);
create or replace function sgroups.list_sg(names sgroups.cname[] default null)
returns table ( "name" sgroups.cname,
                networks sgroups.cname[],
                logs bool,
                trace bool,
                default_action sgroups.chain_default_action
               )
as $$
begin
   return query select sg."name",
                       sg.networks,
                       sg.logs,
                       sg.trace,
                       sg.default_action
                  from sgroups.vu_sg as sg
                 where names is null
                    or sg."name" = any (names);
end;
$$ language plpgsql immutable;

drop function if exists sgroups.find_sg_by_network(sgroups.cname[]) cascade ;
create or replace function sgroups.find_sg_by_network(nw_names sgroups.cname[])
returns table ( "name" sgroups.cname,
                networks sgroups.cname[],
                logs bool,
                trace bool,
                default_action sgroups.chain_default_action
               )
as $$
begin
   return query select sg."name",
                       sg.networks,
                       sg.logs,
                       sg.trace,
                       sg.default_action
                  from sgroups.vu_sg as sg
                 where sg.networks && nw_names;
end;
$$ language plpgsql immutable strict;


drop function if exists sgroups.list_sg_rule(sgroups.cname[], sgroups.cname[]) cascade ;
create or replace function sgroups.list_sg_rule (
    sgfrom sgroups.cname[] default null,
    sgto sgroups.cname[] default null
) returns table ( sg_from sgroups.cname,
                  sg_to sgroups.cname,
                  proto sgroups.proto,
                  ports sgroups.sg_rule_ports[],
                  logs bool
                )
as $$
begin
   return query select r.sg_from,
                       r.sg_to,
                       r.proto,
                       r.ports,
                       r.logs
                  from sgroups.vu_sg_rule as r
                 where ( sgfrom is null or
                         r.sg_from = any (sgfrom) )
                   and ( sgto is null or
                         r.sg_to = any (sgto) );
end;
$$ language plpgsql immutable;

------------------------------- writers ---------------------------
alter type sgroups.row_of__sg
      add attribute logs bool;

alter type sgroups.row_of__sg
      add attribute trace bool;

alter type sgroups.row_of__sg
      add attribute default_action sgroups.chain_default_action;

create or replace function sgroups.sync_sg(op sgroups.sync_op, d sgroups.row_of__sg)
    returns boolean
as $$
declare
    ret bigint;
    badNw sgroups.cname;
begin
    if op = 'del' then
        delete
          from sgroups.tbl_sg
         where "name" = (d)."name"
     returning id
          into ret;
    elsif op = 'upd' then
        update sgroups.tbl_sg
           set logs = (d).logs,
               trace = (d).trace,
               default_action = (d).default_action
         where "name" = (d)."name"
     returning id
          into ret;
    elsif op = 'ups' then
        insert
          into sgroups.tbl_sg("name", logs, trace, default_action)
        values ((d).name, (d).logs, (d).trace, (d).default_action)
            on conflict
               on constraint sg_name_unique
                  do update
                        set logs = (d).logs,
                            trace = (d).trace,
                            default_action = (d).default_action
     returning id
          into ret;
    elsif op = 'ins' then
        insert
          into sgroups.tbl_sg("name", logs, trace, default_action)
        values ((d).name, (d).logs, (d).trace, (d).default_action)
            on conflict
               on constraint sg_name_unique
                  do nothing
     returning id
          into ret;
    end if;
    if ret is not null and op = any (array['upd', 'ups', 'ins']) then
        with o(nw1, nw2) as (
            select t1.nw1, t2.nw2
              from (select unnest((d).networks)) t1(nw1)
                      left outer join lateral ( select "name"
                                                  from sgroups.tbl_network
                                                 where "name" = t1.nw1 ) t2(nw2)
                        on true
        ) select nw1
            from o
           where nw2 is null
           limit 1
            into badNw;

        if badNw is not null then
           raise exception 'unable bind Net(%)-->SG(%) cause such Net does not exist',
                           badNw, (d)."name";
        end if;
        update sgroups.tbl_network
           set sg = null
         where sg = ret;
        update sgroups.tbl_network
           set sg = ret
          from ( select unnest((d).networks) ) t(nw)
         where "name" = t.nw;
    end if;
    return ret is not null;
end;
$$ language plpgsql strict;

alter type sgroups.row_of__sg_rule
       add attribute logs bool;

create or replace function sgroups.sync_sg_rule(op sgroups.sync_op, d sgroups.row_of__sg_rule)
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
               logs = (d).logs
         where sg_from = sgFrom
           and sg_to = sgTo
           and proto = (d).proto
    returning id into ret;
    elsif op = 'ups' then
        insert into sgroups.tbl_sg_rule (sg_from, sg_to, proto, ports, logs)
        values (sgFrom, sgTo, (d).proto, (d).ports, (d).logs)
            on conflict
               on constraint sg_rule_identity
                  do update
                        set ports = (d).ports,
                            logs = (d).logs
     returning id into ret;
    elsif op = 'ins' then
        insert into sgroups.tbl_sg_rule (sg_from, sg_to, proto, ports, logs)
        values (sgFrom, sgTo, (d).proto, (d).ports, (d).logs)
            on conflict
               on constraint sg_rule_identity
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
