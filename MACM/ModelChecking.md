# MACM Graph Database Validation Rules

This document describes a set of **validation rules for nodes and relationships** in a graph database (Neo4j with APOC triggers). The purpose of these rules is to ensure **data integrity, consistency, and semantic correctness** across different types of assets (HW, Virtual, SoftLayer, Service, Network, Party, CSP).

Each rule is enforced via **APOC triggers** that validate nodes and relationships before or after they are created/modified.

---

## Rule 1: Asset Type and Label Consistency
Each node must have an `asset_type` belonging to the allowed set `T`. The pair `(PrimaryLabel, SecondaryLabel)` must match the `(primary_label, secondary_label)` defined in the mapping.

```cypher
CALL apoc.trigger.add(
  'check_asset_type_labels',
  '
  UNWIND coalesce($createdNodes, []) AS n
  WITH n
  WHERE n.type IS NOT NULL

  WITH n, split(n.type, ".")[0] AS plFromType, labels(n) AS lbls
  CALL apoc.util.validate(
    NOT (plFromType IN lbls),
    apoc.text.format(
      "/* %s type=%s expects primary label %s but labels are [%s] */",
      [coalesce(n.name,"<no name>"), n.type, plFromType, apoc.text.join(lbls, ",")]
    ),
    []
  )

  WITH n, plFromType, lbls,
       ["Party","CSP","HW","Network","Service","Virtual","SystemLayer","Data"] AS macro
  WITH n, plFromType, [l IN lbls WHERE l <> plFromType AND NOT l IN macro] AS rest

  WITH n, plFromType, rest,
       [
         {pl:"Party",sl:"Human",types:["Party.Human"]},
         {pl:"Party",sl:"LegalEntity",types:["Party.LegalEntity"]},
         {pl:"Party",sl:"Group",types:["Party.Group"]},
         {pl:"CSP",sl:null,types:["CSP"]},
         {pl:"HW",sl:"MEC",types:["HW.MEC"]},
         {pl:"HW",sl:"HW.GCS",types:["HW.GCS"]},
         {pl:"HW",sl:"UE",types:["HW.UE"]},
         {pl:"HW",sl:"Chassis",types:["HW.Chassis"]},
         {pl:"HW",sl:"Raspberry",types:["HW.Raspberry"]},
         {pl:"HW",sl:"Router",types:["HW.Router"]},
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
         {pl:"SystemLayer",sl:"OS",types:["SystemLayer.OS"]},
         {pl:"SystemLayer",sl:"Firmware",types:["SystemLayer.Firmware"]},
         {pl:"SystemLayer",sl:"HyperVisor",types:["SystemLayer.HyperVisor"]},
         {pl:"SystemLayer",sl:"ContainerRuntime",types:["SystemLayer.ContainerRuntime"]},
         {pl:"Virtual",sl:"VM",types:["Virtual.VM"]},
         {pl:"Virtual",sl:"Container",types:["Virtual.Container"]},
         {pl:"Service",sl:"5G",types:["Service.5G.RAN","Service.5G.AMF","Service.5G.AUSF","Service.5G.NEF","Service.5G.NRF","Service.5G.NSSF","Service.5G.NWDAF","Service.5G.PCF","Service.5G.UDM","Service.5G.UPF"]},
         {pl:"Service",sl:"App",types:["Service.App","Service.Browser","Service.MQTTClient"]},
         {pl:"Service",sl:null,types:["Service"]},
         {pl:"Service",sl:"Server",types:["Service.JobScheduler","Service.SSH","Service.Web","Service.API","Service.DB","Service.NoSQLDB","Service.IDProvider","Service.MQTTBroker","Service.RPCBind"]}
       ] AS mapping

  WITH n, plFromType, rest,
       [m IN mapping WHERE m.pl = plFromType AND n.type IN m.types | m.sl] AS expectedSLsRaw
  WITH n, plFromType, rest,
       [x IN expectedSLsRaw WHERE x IS NOT NULL] AS expectedSome,
       any(x IN expectedSLsRaw WHERE x IS NULL)  AS noneAllowed,
       size(expectedSLsRaw)                      AS hasAnyMapping
  CALL apoc.util.validate(
    hasAnyMapping = 0,
    apoc.text.format(
      "/* %s type=%s PL=%s is not covered by mapping */",
      [coalesce(n.name,"<no name>"), n.type, plFromType]
    ),
    []
  )

  WITH n, plFromType, rest, expectedSome, noneAllowed,
       (CASE WHEN noneAllowed THEN "[]" ELSE "[" + apoc.text.join(expectedSome, ",") + "]" END) AS expectedStr,
       apoc.text.join(rest, ",") AS restStr
  CALL apoc.util.validate(
    (noneAllowed  AND size(rest) <> 0) OR
    (NOT noneAllowed AND (size(rest) <> 1 OR NOT rest[0] IN expectedSome)),
    apoc.text.format(
      "/* %s type=%s PL=%s expected SL(s)=%s but secondary labels are [%s] */",
      [coalesce(n.name,"<no name>"), n.type, plFromType, expectedStr, restStr]
    ),
    []
  )

  RETURN 0;
  ',
  {phase:'before'}
);
```

---

## Rule 2: Single Hosting/Providing per Asset
Each asset must be hosted or provided by **at most** one other node. No service can have multiple hosts or provider.

```cypher
CALL apoc.trigger.add(
	'check_single_host_provide_per_asset',
	'
	MATCH (s)
	OPTIONAL MATCH (hoster)-[r]->(s)
	WHERE type(r) IN ["hosts","provides"]
	WITH s, COUNT(DISTINCT hoster) AS numHosts
	WHERE numHosts > 1
	WITH collect(s.name) AS violations
	CALL apoc.util.validate(
		size(violations) > 0,
		"/*Rule 2 violation: the following service has more than a host/provider:" + apoc.text.join (violations, ",") + "*/",
		[]
	)
	RETURN true
	',
	{phase:'before'}
);
```

---

## Rule 3: Mandatory Hosting/Providing for Services
Each `Service` node must be hosted or provided by **at least** one other node. No service can be orphaned.

```cypher
CALL apoc.trigger.add(
	'check_mandatory_host_provide_for_service',
	'
	MATCH (s:Service)
	OPTIONAL MATCH (hoster)-[r]->(s)
	WHERE type(r) IN ["hosts","provides"]
	WITH s, COUNT(DISTINCT hoster) AS numHosts
	WHERE numHosts < 1
	WITH collect(s.name) AS violations
	CALL apoc.util.validate(
		size(violations) > 0,
		"/*Rule 3 violation: the following service do not have a host/provider:" + apoc.text.join (violations, ",") + "*/",
		[]
	)
	RETURN true
	',
	{phase:'before'}
);
```

---

## Rule 4: Alternate Path for `uses` Relationships
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
		"/*Rule 4 violation: uses relationships without alternative path: " + apoc.text.join(violazioni, ", ") + "*/",
		[]
	)
	RETURN true
	',
	{phase: 'before'}
);
```

---

## Rule 5: Valid Hosting among SystemLayer Nodes
Only `SystemLayer.OS` nodes may host containerization or virtualization environments.

```cypher
CALL apoc.trigger.add(
	'check_SystemLayer_hosts_SystemLayer',
	'
	MATCH (src)-[r:hosts]->(dst)
	WITH head(labels(src)) AS primarySrc, head(labels(dst)) AS primaryDst, src, dst
	WHERE primarySrc = "SystemLayer"
	AND primaryDst = "SystemLayer"
	AND NOT (
		src.type = "SystemLayer.OS" AND
		dst.type IN ["SystemLayer.ContainerRuntime", "SystemLayer.HyperVisor"]
	)
	WITH collect(src.name + " hosts " + dst.name) AS violazioni
	CALL apoc.util.validate(
		size(violazioni) > 0,
		"/*Rule 5 violation: hosting relationships between SystemLayer nodes not valid: " + apoc.text.join(violazioni, ", ")+"*/",
		[]
		)
	RETURN true
		',
	{phase: 'before'}
);
```

---

## Rule 6: SystemLayer Hosting Virtual
- `ContainerRuntime` can only host `Virtual.Container`.
- `HyperVisor` can only host `Virtual.VM`.

```cypher
CALL apoc.trigger.add(
	'check_SystemLayer_hosts_virtual',
	'
	MATCH (src)-[r:hosts]->(dst)
	WITH head(labels(src)) AS primarySrc, head(labels(dst)) AS primaryDst, src, dst
	WHERE primarySrc = "SystemLayer"
	AND primaryDst = "Virtual"
	AND NOT (
		(src.type = "SystemLayer.ContainerRuntime" AND dst.type = "Virtual.Container") OR
		(src.type = "SystemLayer.HyperVisor" AND dst.type = "Virtual.VM")
	)
	WITH collect(src.name + " hosts " + dst.name) AS violazioni
	CALL apoc.util.validate(
		size(violazioni) > 0,
		"/*Rule 6 violation: hosting relationships between SystemLayer and Virtual nodes not valid: " + apoc.text.join(violazioni, ", ")+"*/",
		[]
	)
	RETURN true
	',
	{phase: 'before'}
);
```

---

## Rule 7: SystemLayer Hosting Service
`Service` nodes can only be hosted by `SystemLayer.OS` and `SystemLayer.Firmware` assets.

```cypher 
CALL apoc.trigger.add(
	'check_SystemLayer_hosts_services',
	'
	MATCH (src)-[r:hosts]->(dst)
	WHERE head(labels(src)) = "SystemLayer"
	AND head(labels(dst)) = "Service"
	AND NOT src.type IN ["SystemLayer.Firmware", "SystemLayer.OS"]
	
	WITH collect(src.name + " (type: " + src.type + ")" + " hosts " + dst.name) AS violazioni
	CALL apoc.util.validate(
		size(violazioni) > 0,
		"/*Rule 7 violation: hosting relationships between SystemLayer and Service nodes not valid: " + apoc.text.join(violazioni, ", ") + "*/",
		[]
	)
	RETURN true
	',
	{phase: 'before'}
);
```

---

## Rule 8: Virtual Hosting SystemLayer
If a `Virtual` node hosts a `SystemLayer`, the hosted node must be of type `SystemLayer.OS` or `SystemLayer.Firmware`.

```cypher
CALL apoc.trigger.add(
	'check_virtual_hosts_SystemLayer',
	'
	MATCH (src)-[r:hosts]->(dst)
	WITH head(labels(src)) AS primarySrc, head(labels(dst)) AS primaryDst, src, dst
	WHERE primarySrc = "Virtual"
		AND primaryDst = "SystemLayer"
		AND NOT (dst.type IN ["SystemLayer.OS", "SystemLayer.Firmware"])
	WITH collect(src.name + " hosts " + dst.name) AS violazioni
	CALL apoc.util.validate(
		size(violazioni) > 0,
		"/*Rule 8 violation: hosting relationships between Virtual and SystemLayer nodes not valid: " + apoc.text.join(violazioni, ", ") + "*/",
		[]
	)
	RETURN true
	',
	{phase: 'before'}
);
```

---

## Rule 9: HW Hosting SystemLayer
HW nodes cannot host `SystemLayer.ContainerRuntime`.

```cypher
CALL apoc.trigger.add(
	'check_hw_hosts_SystemLayer',
	'
	MATCH (src)-[r:hosts]->(dst)
	WITH head(labels(src)) AS primarySrc, head(labels(dst)) AS primaryDst, src, dst
	WHERE primarySrc = "HW"
		AND primaryDst = "SystemLayer"
		AND dst.type = "SystemLayer.ContainerRuntime"
	WITH collect(src.name + " hosts " + dst.name) AS violazioni
	CALL apoc.util.validate(
		size(violazioni) > 0,
		"/*Rule 9 violation: hosting relationships between HW and SystemLayer nodes not valid (ContainerRuntime not allowed): " + apoc.text.join(violazioni, ", ") + "*/",
		[]
	)
	RETURN true
	',
	{phase: 'before'}
);
```

---

## Rule 10: Protocol Validity on `connects` and `uses`
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
	
	WITH r, propKey, protocolValue, [vp IN validProtocols WHERE vp[0] = type(r)	AND vp[1] = propKey	AND vp[2] = protocolValue] AS matches
	
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

## Rule 11: Graph Connectivity
The graph must be fully connected; there should be a path between any two nodes.

```cypher
CALL apoc.trigger.add(
  'check_graph_connectivity_global',
  '
  // scegliamo un nodo a caso come sorgente
  MATCH (start)
  WITH start LIMIT 1

  // percorsi di lunghezza 0.. → lo start è incluso nei reachable
  MATCH (start)-[*0..]-(reachable)
  WITH start, collect(DISTINCT id(reachable)) AS reachIds

  // tutti i nodi del grafo
  MATCH (n)
  WITH start, reachIds, collect(id(n)) AS allIds
  WITH start, reachIds, allIds, [x IN allIds WHERE NOT x IN reachIds] AS missingIds

  // nodi non raggiungibili
  OPTIONAL MATCH (m) WHERE id(m) IN missingIds
  WITH start,
       [m IN collect(m) | coalesce(m.name, head(labels(m)), toString(id(m)))] AS notReachable

  CALL apoc.util.validate(
    size(notReachable) > 0,
    "/*Connectivity violation: the graph is not connected. Start node: "
      + coalesce(start.name, head(labels(start)), toString(id(start)))
      + ". Unreachable nodes: " + apoc.text.join(notReachable, ", ") + "*/",
    []
  )
  RETURN true
  ',
  {phase: 'before'}
);
```

---

## Rule 12: Single host/provide per SystemLayer
Each `SystemLayer` node must be hosted or provided by **exactly one** other node. No SystemLayer can be orphaned or have multiple hosts.

```cypher
CALL apoc.trigger.add(
	'check_mandatory_host_provide_for_systemlayer',
	'
	MATCH (s:SystemLayer)
	OPTIONAL MATCH (hoster)-[r]->(s)
	WHERE type(r) IN ["hosts","provides"]
	WITH s, COUNT(DISTINCT hoster) AS numHosts
	WHERE numHosts < 1
	WITH collect(s.name) AS violations
	CALL apoc.util.validate(
		size(violations) > 0,
		"/*Rule 12 violation: the following SystemLayer do not have any host/provider:" + apoc.text.join (violations, ",") + "*/",
		[]
	)
	RETURN true
	',
	{phase:'before'}
);
```

---

## Rule 13: Single host/provide per Virtual
Each `Virtual` node must be hosted or provided by **exactly one** other node. No Virtual can be orphaned or have multiple hosts.
```cypher
CALL apoc.trigger.add(
	'check_mandatory_host_provide_for_virtual',
	'
	MATCH (s:Virtual)
	OPTIONAL MATCH (hoster)-[r]->(s)
	WHERE type(r) IN ["hosts","provides"]
	WITH s, COUNT(DISTINCT hoster) AS numHosts
	WHERE numHosts < 1
	WITH collect(s.name) AS violations
	CALL apoc.util.validate(
		size(violations) > 0,
		"/*Rule 13 violation: the following Virtual do not have any host/provider:" + apoc.text.join (violations, ",") + "*/",
		[]
	)
	RETURN true
	',
	{phase:'before'}
);
```

---

## Rule 14: No cycles allowed for hosts relationship
Ensures acyclicity of the :hosts relation, preventing recursive or circular hosting dependencies among system assets.

```cypher
CALL apoc.trigger.add(
  'check_hosts_acyclic_with_cycles',
  '
  MATCH p = (n)-[:hosts*1..]->(n)
  WITH DISTINCT p,
       [x IN nodes(p) | toString(coalesce(x.name, id(x)))] AS lst
  WITH CASE
         WHEN size(lst) > 1 AND lst[0] = lst[size(lst)-1] THEN lst[0..size(lst)-1]
         ELSE lst
       END AS core
  WHERE size(core) > 0
  WITH [i IN range(0, size(core)-1) |
         apoc.text.join(core[i..] + core[..i] + [core[i]], " -> ")
       ] AS rots
  WITH apoc.coll.min(rots) AS cycleCanon
  WITH apoc.coll.toSet(collect(cycleCanon)) AS cycles
  CALL apoc.util.validate(
    size(cycles) > 0,
    "/*Constraint violation: cycles detected in :hosts hierarchy:\\n" + apoc.text.join(cycles[0..20], "\\n") + "*/",
    []
  )
  RETURN true
  ',
  {phase:'before'}
);
```

---

## Relationship Validity Pattern
Only predefined relationship patterns are allowed.

```cypher
CALL apoc.trigger.add(
  'check_allowed_relationships',
  '
  // relazioni ammesse (macro-primarie)
  WITH [
    ["Party",     "interacts", "Service"],
    ["Party",     "interacts", "HW"],
    ["Party",     "interacts", "Network"],
    ["Party",     "interacts", "Party"],
    ["Party",     "interacts", "Virtual"],
    ["Party",     "interacts", "SystemLayer"],
    ["Party",     "interacts", "CSP"],

    ["Service",   "uses",      "Service"],
    ["Service",   "uses",      "Virtual"],
    ["Service",   "hosts",     "Service"],

    ["Virtual",   "hosts",     "SystemLayer"],

    ["SystemLayer", "hosts",     "SystemLayer"],
    ["SystemLayer", "hosts",     "Virtual"],
    ["SystemLayer", "hosts",     "Service"],
    ["SystemLayer",  "hosts",     "Network"],
    ["SystemLayer", "uses",      "HW"],

    ["HW",        "hosts",     "HW"],
    ["HW",        "hosts",     "SystemLayer"],

    ["CSP",       "provides",  "Service"],
    ["CSP",       "provides",  "Network"],
    ["CSP",       "provides",  "HW"],
    ["CSP",       "provides",  "Virtual"],
    ["CSP",       "provides",  "SystemLayer"],

    ["Network",   "connects",  "Network"],
    ["Network",   "connects",  "Virtual"],
    ["Network",   "connects",  "HW"],
    ["Network",   "connects",  "CSP"]
  ] AS allowed,
  coalesce($createdRelationships, []) AS rels,            // solo le relazioni toccate nel tx
  ["Party","CSP","HW","Network","Service","Virtual","SystemLayer","Data"] AS macro

  UNWIND rels AS r
  WITH allowed, macro, startNode(r) AS src, type(r) AS relType, endNode(r) AS dst

  // primary label robusta: prima macro presente nelle label del nodo
  WITH allowed, relType,
       [m IN macro WHERE m IN labels(src)][0] AS primarySrc,
       [m IN macro WHERE m IN labels(dst)][0] AS primaryDst

  WITH allowed, primarySrc, relType, primaryDst
  WHERE NOT any(rule IN allowed WHERE rule[0]=primarySrc AND rule[1]=relType AND rule[2]=primaryDst)

  WITH collect(coalesce(primarySrc,"<no-PL>") + "-" + relType + "->" + coalesce(primaryDst,"<no-PL>")) AS violations
  CALL apoc.util.validate(
    size(violations) > 0,
    "/*Constraint violated: Unauthorized relationship(s): " + apoc.text.join(violations, ", ")+"*/",
    []
  )
  RETURN true;
  ',
  {phase:'before'}
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
	WITH r, prop, head([c IN cardinalities WHERE (c.rel = type(r)) AND c.prop = prop]) AS c
	WHERE c IS NOT NULL
	WITH r, prop, c,
	CASE
		WHEN r[prop] IS NULL THEN 0
		WHEN r[prop] IS LIST THEN size(r[prop])
		ELSE 1
	END AS valCount
	CALL apoc.util.validate(
		valCount < c.min OR valCount > c.max, "Cardinalità invalida per proprietà \'" + prop + "\' nella relazione di tipo \'" + type(r) + "\': atteso tra " + c.min + " e " + c.max + ", trovato " + valCount,
		[]
	) YIELD value
	
	RETURN null
	',
	{phase:'after'}
);
```
