// Generated by ScalaTS 0.5.9: https://scala-ts.github.io/scala-ts/

export interface VulnerabilitiesDTO {
  containers: (Error | VulnerableContainers);
  nodes: (Error | VulnerableNodes);
}

export function isVulnerabilitiesDTO(v: any): v is VulnerabilitiesDTO {
  return (
    ((v['containers'] && isError(v['containers'])) || (v['containers'] && isVulnerableContainers(v['containers']))) &&
    ((v['nodes'] && isError(v['nodes'])) || (v['nodes'] && isVulnerableNodes(v['nodes'])))
  );
}