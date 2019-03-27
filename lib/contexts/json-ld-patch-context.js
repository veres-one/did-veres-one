module.exports =  {
  "@context": {
    "id": "@id",
    "type": "@type",
    "jldp": "https://w3id.org/json-ld-patch#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "add": "jldp:add",
    "copy": "jldp:copy",
    "frame": {"@id": "jldp:frame", "@type": "@id"},
    "from": "jldp:from",
    "move": "jldp:move",
    "op": "jldp:op",
    "patch": {"@id": "jldp:patch", "@type": "@id", "@container": "@set"},
    "path": "jldp:path",
    "remove": "jldp:remove",
    "replace": "jldp:replace",
    "target": {"@id": "jldp:target", "@type": "@id"},
    "test": "jldp:test",
    "sequence": {"@id": "jldp:sequence", "@type": "xsd:integer"},
    "value": "jldp:value"
  }
}
