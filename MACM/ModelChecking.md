# Graph Database Validation Rules

This document describes a set of **validation rules for nodes and relationships** in a graph database (Neo4j with APOC triggers). The purpose of these rules is to ensure **data integrity, consistency, and semantic correctness** across different types of assets (HW, Virtual, SoftLayer, Service, Network, Party, CSP).

Each rule is enforced via **APOC triggers** that validate nodes and relationships before or after they are created/modified.

---

## Rule 1: Asset Type and Label Consistency
Each node must have an `asset_type` belonging to the allowed set `T`. The pair `(PrimaryLabel, SecondaryLabel)` must match the `(primary_label, secondary_label)` defined in the mapping.

```cypher
CALL apoc.trigger.add(
  'check_asset_type_labels',
  '
  WITH
    coalesce($createdNodes, [])          AS created,
    coalesce($assignedLabels, [])        AS assignedLabels,
    coalesce($assignedNodeProperties, [])    AS assignedProps

  WITH
    [n IN created | id(n)] +
    [x IN assignedLabels | x.nodeId] +
    [x IN assignedProps  | x.nodeId]     AS ids

  WITH apoc.coll.toSet(ids) AS ids
  MATCH (n)
  WHERE id(n) IN ids AND n.type IS NOT NULL

  WITH n, labels(n) AS lbls,
       ["Party","CSP","HW","Network","Service","Data","SoftLayer"] AS macro,
       [
         {pl:"Party",sl:"Human",types:["Party.Human"]},
         {pl:"Party",sl:"Legal Entity",types:["Party.LegalEntity"]},
         {pl:"Party",sl:"Group",types:["Party.Group"]},
         {pl:"CSP",sl:null,types:["CSP"]},
         {pl:"HW",sl:"MEC",types:["HW.MEC"]},
         {pl:"HW",sl:null,types:["HW.Chassis","HW.GCS","HW.HDI","HW.Router","HW.Raspberry"]},
         {pl:"HW",sl:"UE",types:["HW.UE"]},
         {pl:"HW",sl:"IoT",types:["HW.IoT.Device","HW.IoT.Gateway"]},
         {pl:"HW",sl:"Device",types:["HW.Device","HW.HDI"]},
         {pl:"HW",sl:"Server",types:["HW.Server"]},
         {pl:"HW",sl:"Microcontroller",types:["HW.Microcontroller"]},
         {pl:"HW",sl:"SOC",types:["HW.SOC"]},
         {pl:"HW",sl:"PC",types:["HW.PC","HW.PC.LoginNode","HW.PC.DataStorageDisk","HW.PC.SchedulerNode","HW.PC.ComputeNode"]},
         {pl:"Network",sl:null,types:["Network"]},
         {pl:"Network",sl:"WAN",types:["Network.WAN"]},
         {pl:"Network",sl:"LAN",types:["Network.LAN","Network.Wired","Network.WiFi","Network.Virtual"]},
         {pl:"Network",sl:"PAN",types:["Network.PAN"]},
         {pl:"Network",sl:"5G",types:["Network.RAN","Network.Core"]},
         {pl:"Service",sl:"5G",types:["Service.5G.RAN","Service.5G.AMF","Service.5G.AUSF","Service.5G.NEF","Service.5G.NRF","Service.5G.NSSF","Service.5G.NWDAF","Service.5G.PCF","Service.5G.UDM","Service.5G.UPF"]},
         {pl:"Service",sl:"Server",types:["Service.SSH"]},
         {pl:"Service",sl:"IaaS",types:["Service.VM","Service.ContainerRuntime"]},
         {pl:"Service",sl:"SaaS",types:["Service.Container","Service.DB","Service.Web","Service.API","Service.NoSQLDB","Service.JobScheduler","Service.MQTTBroker","Service.MQTTClient"]},
         {pl:"Service",sl:null,types:["Service.IDProvider","Service.App","Service.Browser"]},
         {pl:"SoftLayer",sl:"OS",types:["SoftLayer.OS"]},
         {pl:"SoftLayer",sl:"Firmware",types:["SoftLayer.Firmware"]},
         {pl:"Data",sl:null,types:["Data.DB","Data.Configuration"]}
       ] AS mapping

  WITH n, mapping, macro,
       [x IN macro WHERE x IN labels(n)][0] AS pl,
       [x IN labels(n) WHERE NOT x IN macro][0] AS sl
  WITH n, mapping, coalesce(pl,"") AS pl, coalesce(sl,"") AS sl
  WHERE NOT any(m IN mapping WHERE n.type IN m.types AND m.pl = pl AND coalesce(m.sl,"") = sl)

  CALL apoc.util.validate(
    true,
    "Nodo " + coalesce(n.name,"<senza nome>")
      + " con type=" + n.type
      + " ha label primaria=" + pl
      + " e secondaria=" + (CASE WHEN sl = "" THEN "<nessuna>" ELSE sl END)
      + " non coerenti con la mappatura.",
    []
  )
  RETURN 0;
  ',
  {phase:'before'}
);
```

---

## Rule 2: Single Hosting/Providing for Services
Each `Service` node must be hosted or provided by **exactly one** other node. No service can be orphaned or have multiple hosts.

```cypher
CALL apoc.trigger.add(
'check_single_host_provide_for_service',
'
// Trova i Service che non hanno esattamente un host/provide
MATCH (s:Service)
OPTIONAL MATCH (hoster)-[r]->(s)
WHERE type(r) IN ["hosts","provides"]
WITH s, COUNT(DISTINCT hoster) AS numHosts
WHERE numHosts <> 1
WITH collect(s.name) AS violazioni
CALL apoc.util.validate(
size(violazioni) > 0,
"Regola 2 violata: i seguenti Service non hanno esattamente un host/provide: " + apoc.text.join(violazioni, ", "),
[]
)
RETURN true
',
{phase:'before'}
);
```

---

## Rule 3: Alternate Path for `uses` Relationships
Every `uses` relationship must have an alternative path between the two nodes without relying on another `uses`.

```cypher
CALL apoc.trigger.add(
'check_alternate_path_for_uses',
'
MATCH (a)-[r:uses]->(b)
WHERE NOT EXISTS {
MATCH p=(a)-[*]-(b)
WHERE ALL(rel IN relationships(p) WHERE type(rel) <> "uses")
}
WITH collect(a.name + "->" + b.name) AS violazioni
CALL apoc.util.validate(
size(violazioni) > 0,
"Regola 3 violata: Relazioni uses senza percorso alternativo: " + apoc.text.join(violazioni, ", "),
[]
)
RETURN true
',
{phase: 'before'}
);

```

---

## Rule 4: Valid Hosting among SoftLayer Nodes
Only `SoftLayer.OS` nodes may host containerization or virtualization environments.

```cypher
CALL apoc.trigger.add(
'check_softlayer_hosts_softlayer',
'
MATCH (src)-[r:hosts]->(dst)
WITH head(labels(src)) AS primarySrc, head(labels(dst)) AS primaryDst, src, dst
WHERE primarySrc = "SoftLayer"
AND primaryDst = "SoftLayer"
AND NOT (
src.type = "SoftLayer.OS" AND
dst.type IN ["SoftLayer.ContainerRuntime", "SoftLayer.HyperVisor"]
)
WITH collect(src.name + " hosts " + dst.name) AS violazioni
CALL apoc.util.validate(
size(violazioni) > 0,
"Regola 4 violata: Relazioni hosts SoftLayer non valide: " + apoc.text.join(violazioni, ", "),
[]
)
RETURN true
',
{phase: 'before'}
);

```

---

## Rule 5: SoftLayer Hosting Virtual
- `ContainerRuntime` can only host `Virtual.Container`.
- `HyperVisor` can only host `Virtual.VM`.

```cypher
CALL apoc.trigger.add(
'check_softlayer_hosts_virtual',
'
MATCH (src)-[r:hosts]->(dst)
WITH head(labels(src)) AS primarySrc, head(labels(dst)) AS primaryDst, src, dst
WHERE primarySrc = "SoftLayer"
AND primaryDst = "Virtual"
AND NOT (
(src.type = "SoftLayer.ContainerRuntime" AND dst.type = "Virtual.Container") OR
(src.type = "SoftLayer.HyperVisor" AND dst.type = "Virtual.VM")
)
WITH collect(src.name + " hosts " + dst.name) AS violazioni
CALL apoc.util.validate(
size(violazioni) > 0,
"Regola 5 violata: Relazioni hosts SoftLayer→Virtual non valide: " + apoc.text.join(violazioni, ", "),
[]
)
RETURN true
',
{phase: 'before'}
);

```

---

## Rule 6: Virtual Hosting SoftLayer
If a `Virtual` node hosts a `SoftLayer`, the hosted node must be of type `SoftLayer.OS` or `SoftLayer.Firmware`.

```cypher
CALL apoc.trigger.add(
'check_virtual_hosts_softlayer',
'
MATCH (src)-[r:hosts]->(dst)
WITH head(labels(src)) AS primarySrc, head(labels(dst)) AS primaryDst, src, dst
WHERE primarySrc = "Virtual"
AND primaryDst = "SoftLayer"
AND NOT (dst.type IN ["SoftLayer.OS", "SoftLayer.Firmware"])
WITH collect(src.name + " hosts " + dst.name) AS violazioni
CALL apoc.util.validate(
size(violazioni) > 0,
"Regola 6 violata: Relazioni hosts Virtual→SoftLayer non valide: " + apoc.text.join(violazioni, ", "),
[]
)
RETURN true
',
{phase: 'before'}
);

```

---

## Rule 7: HW Hosting SoftLayer
HW nodes cannot host `SoftLayer.ContainerRuntime`.

```cypher
CALL apoc.trigger.add(
'check_hw_hosts_softlayer',
'
MATCH (src)-[r:hosts]->(dst)
WITH head(labels(src)) AS primarySrc, head(labels(dst)) AS primaryDst, src, dst
WHERE primarySrc = "HW"
AND primaryDst = "SoftLayer"
AND dst.type = "SoftLayer.ContainerRuntime"
WITH collect(src.name + " hosts " + dst.name) AS violazioni
CALL apoc.util.validate(
size(violazioni) > 0,
"Regola 7 violata: Relazioni hosts HW→SoftLayer non valide (ContainerRuntime non ammesso): " + apoc.text.join(violazioni, ", "),
[]
)
RETURN true
',
{phase: 'before'}
);

```

---

## Rule 8: Protocol Validity on `connects` and `uses`
Protocols defined in relationship properties must belong to a predefined set.

```cypher
CALL apoc.trigger.add(
'checkProtocolValidity',
'
WITH [
["connects", "data_link_protocol", "ARP"],
["connects", "data_link_protocol", "Ethernet"],
["connects", "data_link_protocol", "Zigbee"],
["connects", "data_link_protocol", "Wi-Fi (IEEE 802.11)"],
["connects", "network_protocol", "BGP"],
["connects", "network_protocol", "IPv4"],
["connects", "network_protocol", "IPv6"],
["connects", "network_protocol", "IPSec"],
["connects", "transport_protocol", "QUIC"],
["connects", "transport_protocol", "SCTP"],
["connects", "transport_protocol", "UDP"],
["connects", "transport_protocol", "TCP"],
["connects", "presentation_protocol", "DTLS"],
["connects", "presentation_protocol", "TLS"],
["connects", "presentation_protocol", "SSL"],
["connects", "application_protocol", "HTTP"],
["connects", "application_protocol", "Mavlink"],
["connects", "application_protocol", "NFS"],
["connects", "application_protocol", "SMB"],
["connects", "application_protocol", "LDAP"],
["connects", "application_protocol", "DHCP"],
["connects", "application_protocol", "FTP"],
["connects", "application_protocol", "SSH"],
["connects", "application_protocol", "DNS"],
["connects", "application_protocol", "Telnet"],
["connects", "application_protocol", "MQTT"],
["uses", "data_link_protocol", "ARP"],
["uses", "data_link_protocol", "Ethernet"],
["uses", "data_link_protocol", "Zigbee"],
["uses", "data_link_protocol", "Wi-Fi (IEEE 802.11)"],
["uses", "network_protocol", "BGP"],
["uses", "network_protocol", "IPv4"],
["uses", "network_protocol", "IPv6"],
["uses", "network_protocol", "IPSec"],
["uses", "transport_protocol", "QUIC"],
["uses", "transport_protocol", "SCTP"],
["uses", "transport_protocol", "UDP"],
["uses", "transport_protocol", "TCP"],
["uses", "presentation_protocol", "DTLS"],
["uses", "presentation_protocol", "TLS"],
["uses", "presentation_protocol", "SSL"],
["uses", "application_protocol", "HTTP"],
["uses", "application_protocol", "Mavlink"],
["uses", "application_protocol", "NFS"],
["uses", "application_protocol", "SMB"],
["uses", "application_protocol", "LDAP"],
["uses", "application_protocol", "DHCP"],
["uses", "application_protocol", "FTP"],
["uses", "application_protocol", "SSH"],
["uses", "application_protocol", "DNS"],
["uses", "application_protocol", "Telnet"],
["uses", "application_protocol", "MQTT"]
] AS validProtocols

UNWIND apoc.trigger.propertiesByKey("connects", "uses") AS changedEdges
MATCH ()-[r]->()
WHERE id(r) = changedEdges.id
AND type(r) IN ["connects","uses"]

UNWIND keys(r) AS propKey
WITH r, propKey, validProtocols
WHERE propKey IN ["application_protocol","transport_protocol","network_protocol","data_link_protocol","presentation_protocol"]

UNWIND CASE
WHEN r[propKey] IS NULL THEN []
WHEN r[propKey] IS LIST THEN r[propKey]
ELSE [r[propKey]]
END AS protocolValue

WITH r, propKey, protocolValue,
[vp IN validProtocols
WHERE vp[0] = type(r)
AND vp[1] = propKey
AND vp[2] = protocolValue] AS matches

CALL apoc.do.when(
size(matches) = 0,
"SET r.protocol_error = coalesce(r.protocol_error, []) + [apoc.text.join(['Invalid protocol', protocolValue, 'on property', propKey, 'for relationship type', type(r)], ' ')] RETURN r",
"REMOVE r.protocol_error RETURN r",
{r:r, protocolValue:protocolValue, propKey:propKey}
) YIELD value


RETURN null
',
{phase:'after'}
);

```

---

## Rule 9: HW Hosting Services
HW nodes can only host `SoftLayer.OS` or `SoftLayer.Firmware`.

```cypher
CALL apoc.trigger.add(
'check_hw_hosts_services',
'
MATCH (src)-[r:hosts]->(dst)
WHERE
head(labels(src)) = "HW"
AND head(labels(dst)) = "SoftLayer"
AND NOT dst.type IN ["SoftLayer.Firmware", "SoftLayer.OS"]

WITH collect(src.name + " hosts " + dst.name + " (type: " + dst.type + ")") AS violazioni
CALL apoc.util.validate(
size(violazioni) > 0,
"Regola 9 violata: Nodi HW possono hostare solo SoftLayer di tipo Firmware o OS. Violazioni: "
+ apoc.text.join(violazioni, ", "),
[]
)
RETURN true
',
{phase: 'before'}
);

```

---

## Relationship Validity Pattern
Only predefined relationship patterns are allowed.

```cypher
CALL apoc.trigger.add(
'validateRelationshipPattern',
'
WITH [
{source: "Party", rel: "interacts", target: "Service"},
{source: "Party", rel: "interacts", target: "HW"},
{source: "Party", rel: "interacts", target: "Network"},
{source: "Party", rel: "interacts", target: "Party"},
{source: "Party", rel: "interacts", target: "Virtual"},
{source: "Party", rel: "interacts", target: "SoftLayer"},
{source: "Party", rel: "interacts", target: "CSP"},
{source: "Service", rel: "uses", target: "Service"},
{source: "Service", rel: "uses", target: "Virtual"},
{source: "Service", rel: "hosts", target: "Service"},
{source: "Virtual", rel: "hosts", target: "SoftLayer"},
{source: "SoftLayer", rel: "hosts", target: "SoftLayer"},
{source: "SoftLayer", rel: "hosts", target: "Virtual"}, {source: "SoftLayer", rel: "hosts", target: "Service"}, 
{source: "HW", rel: "hosts", target: "HW"},
{source: "HW", rel: "hosts", target: "SoftLayer"},
{source: "CSP", rel: "provides", target: "Service"},
{source: "CSP", rel: "provides", target: "Network"},
{source: "CSP", rel: "provides", target: "HW"},
{source: "CSP", rel: "provides", target: "Virtual"},
{source: "CSP", rel: "provides", target: "SoftLayer"},
{source: "Network", rel: "connects", target: "Network"},
{source: "Network", rel: "connects", target: "Virtual"},
{source: "Network", rel: "connects", target: "SoftLayer"},
{source: "Network", rel: "connects", target: "HW"},
{source: "Network", rel: "connects", target: "CSP"}
] AS validPatterns

UNWIND $createdRelationships AS rel
MATCH (source)-[r]->(target)
WHERE id(r) = rel.id
WITH source, r, target, validPatterns
WHERE NOT ANY(pattern IN validPatterns WHERE
pattern.source = head(labels(source)) AND
pattern.rel = type(r) AND
pattern.target = head(labels(target))
)
CALL apoc.util.validate(
true,
"Relazione non valida secondo Table 1: " + type(r) + " tra " + head(labels(source)) + " e " + head(labels(target)),
[]
)
YIELD value
RETURN value
',
{phase:'after'}
);

```

---

## Check Protocol Cardinalities
Properties on nodes and relationships must respect predefined min/max cardinalities.

```cypher
CALL apoc.trigger.add('checkCardinalities',
'
WITH [
{rel: "", prop: "id", min: 1, max: 1},
{rel: "", prop: "name", min: 1, max: 1},
{rel: "", prop: "asset type", min: 1, max: 1},
{rel: "connects", prop: "data link protocol", min: 0, max: 1},
{rel: "connects", prop: "network protocol", min: 0, max: 1},
{rel: "connects", prop: "application protocol", min: 0, max: 1},
{rel: "uses", prop: "transport protocol", min: 0, max: 1},
{rel: "uses", prop: "session protocol", min: 0, max: 1},
{rel: "uses", prop: "presentation protocol", min: 0, max: 1},
{rel: "uses", prop: "application protocol", min: 0, max: 999999}  // +∞ approssimato
] AS cardinalities

// Controlla proprietà sui nodi create o modificate
UNWIND $createdNodes AS node
WITH node, cardinalities
UNWIND keys(node) AS prop
WITH node, prop, cardinalities
WITH node, prop,
head([c IN cardinalities WHERE c.rel = "" AND c.prop = prop]) AS c
WHERE c IS NOT NULL
WITH node, prop, c,
CASE
WHEN node[prop] IS NULL THEN 0
WHEN node[prop] IS LIST THEN size(node[prop])
ELSE 1
END AS valCount
CALL apoc.util.validate(valCount < c.min OR valCount > c.max,
"Cardinalità invalida per proprietà \'" + prop + "\' nel nodo con id " + toString(id(node)) + ": atteso tra " + c.min + " e " + c.max + ", trovato " + valCount,
[]
) YIELD value

// Controlla proprietà sulle relazioni create o modificate
WITH cardinalities
UNWIND $createdRelationships AS relId
MATCH ()-[r]->()
WHERE id(r) = relId.id
WITH r, cardinalities
UNWIND keys(r) AS prop
WITH r, prop, cardinalities
WITH r, prop,
head([c IN cardinalities WHERE (c.rel = type(r)) AND c.prop = prop]) AS c
WHERE c IS NOT NULL
WITH r, prop, c,
CASE
WHEN r[prop] IS NULL THEN 0
WHEN r[prop] IS LIST THEN size(r[prop])
ELSE 1
END AS valCount
CALL apoc.util.validate(valCount < c.min OR valCount > c.max,
"Cardinalità invalida per proprietà \'" + prop + "\' nella relazione di tipo \'" + type(r) + "\': atteso tra " + c.min + " e " + c.max + ", trovato " + valCount,
[]
) YIELD value

RETURN null
',
{phase:'after'}
);

```

---

## Allowed Relationships Constraint
Defines which node-to-node relationships are allowed. Any deviation is rejected.

```cypher
CALL apoc.trigger.add(
'check_allowed_relationships',
'
// Definizione relazioni ammesse
WITH [
["Party",      "interacts", "Service"],
["Party",      "interacts", "HW"],
["Party",      "interacts", "Network"],
["Party",      "interacts", "Party"],
["Party",      "interacts", "Virtual"],
["Party",      "interacts", "SoftLayer"],
["Party",      "interacts", "CSP"],
["Service",    "uses",      "Service"],
["Service",    "uses",      "Virtual"],
["Service",    "hosts",     "Service"],
["Virtual",    "hosts",     "SoftLayer"],
["SoftLayer",  "hosts",     "SoftLayer"],
["SoftLayer",  "hosts",     "Virtual"],
["SoftLayer",  "hosts",     "Service"],
["HW",         "hosts",     "HW"],
["HW",         "hosts",     "SoftLayer"],
["CSP",        "provides",  "Service"],
["CSP",        "provides",  "Network"],
["CSP",        "provides",  "HW"],
["CSP",        "provides",  "Virtual"],
["CSP",        "provides",  "SoftLayer"],
["Network",    "connects",  "Network"],
["Network",    "connects",  "Virtual"],
["Network",    "connects",  "SoftLayer"],
["Network",    "connects",  "HW"],
["Network",    "connects",  "CSP"]
] AS allowed

// Controlla ogni relazione del MACM
MATCH (src)-[r]->(dst)
WITH head(labels(src)) AS primarySrc,
type(r) AS relType,
head(labels(dst)) AS primaryDst,
allowed
WHERE NOT any(rule IN allowed WHERE
rule[0] = primarySrc AND
rule[1] = relType AND
rule[2] = primaryDst
)
WITH collect(primarySrc + "-" + relType + "->" + primaryDst) AS violations
CALL apoc.util.validate(
size(violations) > 0,
"Constraint violated: Unauthorized relationship(s): " + apoc.text.join(violations, ", "),
[]
)
RETURN true
',
{phase: 'before'}
);
```
