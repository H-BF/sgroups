-- +goose Up
-- +goose StatementBegin
create schema sgroups;

--------------------------------------------- AGGREGATES ----------------------------------------------

drop type if exists sgroups.i4mr_any_intersect_state cascade;
create type sgroups.i4mr_any_intersect_state as (
    overlapped boolean,
    state int4multirange
);

drop function if exists sgroups.i4mr_any_intersect_s(sgroups.i4mr_any_intersect_state, int4multirange) cascade;
create or replace function sgroups.i4mr_any_intersect_s(s sgroups.i4mr_any_intersect_state, val int4multirange)
    returns sgroups.i4mr_any_intersect_state
as $$
    select case
             when val is null or (s).overlapped
                then s
             when (s).state && val
                then ROW(true, (s).state * val)::sgroups.i4mr_any_intersect_state
                else ROW(false, (s).state + val)::sgroups.i4mr_any_intersect_state
           end;
$$ language sql immutable strict;

drop function if exists sgroups.i4mr_any_intersect_f(sgroups.i4mr_any_intersect_state) cascade;
create or replace function sgroups.i4mr_any_intersect_f(v sgroups.i4mr_any_intersect_state)
    returns boolean
as $$
    select (v).overlapped;
$$ language sql immutable strict;

drop aggregate if exists sgroups.i4mr_any_intersect(int4multirange) cascade ;
create aggregate sgroups.i4mr_any_intersect(int4multirange) (
    stype = sgroups.i4mr_any_intersect_state,
    sfunc = sgroups.i4mr_any_intersect_s,
    finalfunc = sgroups.i4mr_any_intersect_f,
    initcond = '(false, "{}")'
);
comment on aggregate sgroups.i4mr_any_intersect(int4multirange)
                  is 'it detects if any part in array of int4 multi range has intersection';

---------------------------------- TYPES & DOMAINS -------------------------------------

drop type if exists sgroups.proto cascade;
create type sgroups.proto as enum (
   'tcp',
   'udp'
);
comment on type sgroups.proto is 'transport protocol in IP net';

drop domain if exists sgroups.port_ranges cascade;
create domain sgroups.port_ranges
           as int4multirange
   constraint port_ranges_correctness
        check (
            value <@ '[1, 65536)'::int4range
        )
   constraint port_ranges_emptiness
        check (
            not (value = '{}')
        );
comment on domain sgroups.port_ranges
     is 'port ranges used by Security Group Rule';


drop domain if exists sgroups.cname cascade;
create domain sgroups.cname
           as text
   constraint cname_length
        check (
            length(value) < 256
        )
   constraint cname_validity
        check (
            (value ~ '^\S') and (value ~ '\S$')
        );
comment on domain sgroups.cname is 'Common Name type';


drop type if exists sgroups.sg_rule_ports_prototype cascade;
create type sgroups.sg_rule_ports_prototype as (
   s sgroups.port_ranges,
   d sgroups.port_ranges
);

drop domain if exists sgroups.sg_rule_ports cascade;
create domain sgroups.sg_rule_ports
           as sgroups.sg_rule_ports_prototype
   constraint "S_or_D_presence"
        check (
            coalesce((value).s, (value).d) is not null
        );
comment on domain sgroups.sg_rule_ports
     is 'sg_rule_ports represents Source and Destination port in SG Rule';

--------------------------------------- function used in checks ---------------------------------------

drop function if exists sgroups.s_ports_dont_intersect(sgroups.sg_rule_ports[]);
create or replace function sgroups.s_ports_dont_intersect(src sgroups.sg_rule_ports[])
    returns boolean
as $$
    declare
        ret boolean := false;
    begin
        with items as (
           select unnest(src) as value
        ) select sgroups.i4mr_any_intersect((value).s)
            from items
            into ret;
        return not ret;
    end;
$$ language plpgsql;
comment on function sgroups.s_ports_dont_intersect
     is 'check S ports array has not intersections';


drop function if exists sgroups.ts() cascade;
create or replace function sgroups.ts()
    returns timestamptz
as $$
begin
    return now();
end;
$$ language plpgsql immutable;
comment on function sgroups.ts
     is 'this is simple "Tiemsatmp" function but with "immutable" flag';

---------------------------------- TABLES ----------------------------------

drop table if exists sgroups.tbl_sg cascade;
create table sgroups.tbl_sg (
    id bigint generated always as identity primary key,
    name sgroups.cname not null,
    constraint sg_name_unique
        unique (name)
);
comment on table sgroups.tbl_sg is 'Security Groups  aka SG';
comment on column sgroups.tbl_sg."name"  is 'SG unique name';

drop table if exists sgroups.tbl_network cascade ;
create table sgroups.tbl_network (
    id bigint generated always as identity primary key,
    sg bigint,
    name sgroups.cname not null,
    network cidr not null,
    constraint network_name_uniqueness
        unique (name),
    constraint prevent_networks_intersections
       exclude using GIST (network inet_ops with &&)
            deferrable initially deferred,
    constraint fk_network___sg
       foreign key(sg) references sgroups.tbl_sg(id)
            on delete set null
            on update restrict
            deferrable initially deferred
);
comment on table sgroups.tbl_network is 'IP Subnets';
comment on column sgroups.tbl_network."name" is 'Network unique name';
comment on column sgroups.tbl_network.sg is 'reference to SG which network can belong to';
comment on constraint prevent_networks_intersections on sgroups.tbl_network
     is 'checks and prevents networks intersections';
comment on constraint fk_network___sg on sgroups.tbl_network
     is 'foreign key to SG';

drop table if exists sgroups.tbl_sg_rule cascade ;
create table sgroups.tbl_sg_rule (
    id bigint generated always as identity primary key,
    sg_from bigint not null,
    sg_to bigint not null,
    proto sgroups.proto not null,
    ports sgroups.sg_rule_ports[],
    constraint sg_rule_identity
        unique (sg_from, sg_to, proto),
    constraint "S_ports_dont_intersect"
         check (
             sgroups.s_ports_dont_intersect(ports)
         ),
    constraint fk_sg_rule___sg_from
       foreign key(sg_from) references sgroups.tbl_sg(id)
            on delete cascade
            on update restrict
            deferrable initially deferred,
    constraint fk_sg_rule___sg_to
        foreign key(sg_to) references sgroups.tbl_sg(id)
            on delete cascade
            on update restrict
            deferrable initially deferred
);
comment on table sgroups.tbl_sg_rule
     is 'Security Group rule represents firewall acceptance rule';
comment on column sgroups.tbl_sg_rule.sg_from is 'SG-from is net packet source';
comment on column sgroups.tbl_sg_rule.sg_to is 'SG-to is net packet destination';
comment on column sgroups.tbl_sg_rule.proto is 'proto is network transport protocol';
comment on constraint sg_rule_identity on sgroups.tbl_sg_rule
     is 'SG identity(SG-From, SG-To, proto) is unique key to firewall rule';
comment on column sgroups.tbl_sg_rule.ports
     is 'ports is variety of Source and Destination ports multi ranges';
comment on constraint "S_ports_dont_intersect" on sgroups.tbl_sg_rule
     is 'checks and prevents any Source ports intersections';
comment on constraint fk_sg_rule___sg_from on sgroups.tbl_sg_rule
     is 'reference to source SG';
comment on constraint fk_sg_rule___sg_to on sgroups.tbl_sg_rule
     is 'reference to destination SG';

drop table if exists sgroups.tbl_sync_status;
create table sgroups.tbl_sync_status(
    id bigint generated always as identity primary key,
    total_affected_rows bigint not null,
    updated_at timestamptz generated always as ( sgroups.ts() ) stored,
    constraint total_rows_affected_positive
         check (
            total_affected_rows > 0
         )
);


drop view if exists sgroups.vu_sg cascade;
create view sgroups.vu_sg as
select sg."name",
       nws.networks
from sgroups.tbl_sg as sg
join lateral (
       select array_agg(nw."name") as networks
         from sgroups.tbl_network as nw
        where nw.sg = sg.id
     ) nws on true;

drop view if exists sgroups.vu_sg_rule cascade;
create or replace view sgroups.vu_sg_rule as
select (select "name" from sgroups.tbl_sg where id = R.sg_from) as sg_from,
       (select "name" from sgroups.tbl_sg where id = R.sg_to) as sg_to,
       proto,
       ports
  from sgroups.tbl_sg_rule as R;


--------------------------------------- SUGAR ---------------------------------------

drop function if exists sgroups.simpleRulePorts(sgroups.port_ranges, sgroups.port_ranges) cascade ;
create or replace function sgroups.simpleRulePorts(s sgroups.port_ranges, d sgroups.port_ranges)
    returns sgroups.sg_rule_ports[]
as $$
begin
    return array[ row(s, d) ];
end;
$$ language plpgsql immutable;

drop operator if exists public.>-> (sgroups.port_ranges, sgroups.port_ranges) cascade ;
create operator public.>-> (
    function = sgroups.simpleRulePorts,
    leftarg = sgroups.port_ranges,
    rightarg = sgroups.port_ranges
);
comment on operator public.>->(sgroups.port_ranges, sgroups.port_ranges)
     is 'operator >-> helps as to construct ports array used in table tbl_sg_rules';

--------------------------------------- READERS ---------------------------------------

drop function if exists sgroups.list_networks(sgroups.cname[]) cascade ;
create or replace function sgroups.list_networks(names sgroups.cname[] default null)
returns table ( "name" sgroups.cname,
                network cidr
              )
as $$
begin
   return query select nw."name",
                       nw.network
                  from sgroups.tbl_network as nw
                 where names is null
                    or nw."name" = any (names);
end;
$$ language plpgsql immutable ;


drop function if exists sgroups.find_networks_from_IP(inet[]) cascade ;
create or replace function sgroups.find_networks_from_IP(ips inet[])
    returns table ( "name" sgroups.cname,
                    network cidr,
                    matched inet[]
                  )
as $$
begin
    return query select nw."name",
                        nw.network,
                        array_agg(x.ip) as matched
                   from sgroups.tbl_network as nw
                   join (select distinct unnest(ips) as ip) x
                     on nw.network >>= x.ip
                  group by nw."name",
                           nw.network;
end;
$$ language plpgsql immutable strict;


drop function if exists sgroups.list_sg(sgroups.cname[]) cascade ;
create or replace function sgroups.list_sg(names sgroups.cname[] default null)
returns table ( "name" sgroups.cname,
                networks sgroups.cname[]
              )
as $$
begin
   return query select sg."name",
                       sg.networks
                  from sgroups.vu_sg as sg
                 where names is null
                    or sg."name" = any (names);
end;
$$ language plpgsql immutable;


drop function if exists sgroups.find_sg_by_network(sgroups.cname[]) cascade ;
create or replace function sgroups.find_sg_by_network(nw_names sgroups.cname[])
returns table ( "name" sgroups.cname,
                networks sgroups.cname[]
              )
as $$
begin
   return query with sgs(sg_name, sg_networks) as (
                   select sg."name",
                          ( select array_agg(nw."name")
                              from sgroups.tbl_network as nw
                             where nw.sg = sg.id ) as networks
                     from sgroups.tbl_sg as sg
                ) select sg_name,
                         sg_networks
                    from sgs
                   where sg_networks && nw_names;
end;
$$ language plpgsql immutable strict;



drop function if exists sgroups.list_sg_rule(sgroups.cname[], sgroups.cname[]) cascade ;
create or replace function sgroups.list_sg_rule (
    sgfrom sgroups.cname[] default null,
    sgto sgroups.cname[] default null
) returns table ( sg_from sgroups.cname,
                  sg_to sgroups.cname,
                  proto sgroups.proto,
                  ports sgroups.sg_rule_ports[]
                )
as $$
begin
   return query with rules(sg_f, sg_t, r_proto, r_ports)
                  as ( select ( select sg."name"
                                  from sgroups.tbl_sg as sg
                                 where sg.id = rule.sg_from ),
                              ( select sg."name"
                                  from sgroups.tbl_sg as sg
                                 where sg.id = rule.sg_to ),
                              rule.proto,
                              rule.ports
                         from sgroups.tbl_sg_rule as rule
                     ) select sg_f,
                              sg_t,
                              r_proto,
                              r_ports
                         from rules
                        where ( sgfrom is null or
                                sg_f = any (sgfrom) )
                          and ( sgto is null or
                                sg_t = any (sgto) );
end;
$$ language plpgsql immutable;

--------------------------------------- WRITERS ---------------------------------------

drop type if exists sgroups.sync_op cascade ;
create domain sgroups.sync_op
           as varchar(3)
   constraint sync_op_value
        check (
            value is not null and
            value = any (array['upd', 'ups', 'ins', 'del']) --update, upsert, insert, delete
        );
comment on domain sgroups.sync_op is 'type operation of UPDATE, UPSERT, DELETE';

drop type if exists sgroups.row_of__sg cascade;
create type sgroups.row_of__sg as (
    "name" sgroups.cname,
    networks sgroups.cname[]
);

drop type if exists sgroups.row_of_sg_rule cascade ;
create type sgroups.row_of__sg_rule as (
    sg_from sgroups.cname,
    sg_to sgroups.cname,
    proto sgroups.proto,
    ports sgroups.sg_rule_ports[]
);


drop function if exists sgroups.sync_sg(sgroups.sync_op, sgroups.row_of__sg);
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
         select id
           from sgroups.tbl_sg
          where "name" = (d)."name"
           into ret;
   elsif op = 'ups' then
         insert
           into sgroups.tbl_sg("name")
         values ((d).name)
             on conflict
                on constraint sg_name_unique
                   do update
                         set "name" = excluded."name"
      returning id
           into ret;
   elsif op = 'ins' then
         insert
           into sgroups.tbl_sg("name")
         values ((d).name)
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


drop type if exists sgroups.row_of__network cascade ;
create type sgroups.row_of__network as (
    "name" sgroups.cname,
    network cidr
);

drop function if exists sgroups.sync_network(sgroups.sync_op, sgroups.row_of__network);
create or replace function sgroups.sync_network(op sgroups.sync_op, d sgroups.row_of__network)
returns boolean
as $$
    declare ret bigint;
begin
   if op = 'upd' then
         update sgroups.tbl_network
            set network = (d).network
          where "name" = (d).name
      returning id into ret;
   elsif op = 'del' then
         delete
           from sgroups.tbl_network
          where "name" = (d).name
      returning id into ret;
   elsif op = 'ups' then
         insert
           into sgroups.tbl_network("name", network)
         values ((d).name, (d).network)
             on conflict
                on constraint network_name_uniqueness
                   do update set network = (d).network
      returning id into ret;
   elsif op = 'ins' then
         insert
           into sgroups.tbl_network("name", network)
         values ((d).name, (d).network)
             on conflict
                on constraint network_name_uniqueness
                   do nothing
      returning id into ret;
   end if;
   return ret is not null;
end;
$$ language plpgsql strict;


drop function if exists sgroups.sync_sg_rule(sgroups.sync_op, sgroups.row_of__sg_rule);
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
          set ports = (d).ports
        where sg_from = sgFrom
          and sg_to = sgTo
          and proto = proto
    returning id into ret;
   elsif op = 'ups' then
       insert into sgroups.tbl_sg_rule (sg_from, sg_to, proto, ports)
                   values (sgFrom, sgTo, (d).proto, (d).ports)
           on conflict
              on constraint sg_rule_identity
                 do update set ports = (d).ports
    returning id into ret;
   elsif op = 'ins' then
       insert into sgroups.tbl_sg_rule (sg_from, sg_to, proto, ports)
                   values (sgFrom, sgTo, (d).proto, (d).ports)
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
drop schema if exists sgroups cascade;
-- +goose StatementEnd
