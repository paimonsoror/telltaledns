{{- define "telltale.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "telltale.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else if contains (include "telltale.name" .) .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "telltale.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "telltale.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "telltale.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "telltale.selectorLabels" -}}
app.kubernetes.io/name: {{ include "telltale.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: all
{{- end }}

{{/* The DNS port inside the pod: 53 on the host network, else dnsPort. */}}
{{- define "telltale.dnsPort" -}}
{{- if .Values.hostNetwork }}53{{ else }}{{ .Values.dnsPort }}{{ end }}
{{- end }}

{{/* REQ: DNS-002/003 — encrypted DNS is on, and the TLS Secret that serves it. */}}
{{- define "telltale.encrypted" -}}
{{- if or .Values.encrypted.dot.enabled .Values.encrypted.doh.enabled .Values.encrypted.doq.enabled }}true{{ end }}
{{- end }}
{{- define "telltale.tlsSecret" -}}
{{- if .Values.encrypted.tls.certManager.enabled }}{{ include "telltale.fullname" . }}-dns-tls{{ else }}{{ .Values.encrypted.tls.secretName }}{{ end }}
{{- end }}
{{/* Ports inside the pod: the Service port on the host network, else an unprivileged one. */}}
{{- define "telltale.dotPort" -}}
{{- if .Values.hostNetwork }}{{ .Values.encrypted.dot.port }}{{ else }}8853{{ end }}
{{- end }}
{{- define "telltale.dohPort" -}}
{{- if .Values.hostNetwork }}{{ .Values.encrypted.doh.port }}{{ else }}8443{{ end }}
{{- end }}
{{- define "telltale.doqPort" -}}
{{- if .Values.hostNetwork }}{{ .Values.encrypted.doq.port }}{{ else }}8853{{ end }}
{{- end }}

{{/* REQ: CLU-009 — mode: scaled. */}}
{{- define "telltale.scaled" -}}
{{- if eq .Values.mode "scaled" }}true{{ end }}
{{- end }}
{{/* Every TelltaleDNS pod of this release (DNS goes to all of them in scaled mode). */}}
{{- define "telltale.podLabels" -}}
app.kubernetes.io/name: {{ include "telltale.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "telltale.resolverLabels" -}}
{{ include "telltale.podLabels" . }}
app.kubernetes.io/component: resolver
{{- end }}
{{- define "telltale.clusterSecret" -}}
{{- .Values.cluster.bootstrapSecret.existingSecret | default (printf "%s-cluster" (include "telltale.fullname" .)) }}
{{- end }}
{{/* REQ: FLT-017 — the ServiceAccount the controller (or allInOne pod) uses to watch pods. */}}
{{- define "telltale.serviceAccountName" -}}
{{- .Values.kubernetes.rbac.serviceAccountName | default (printf "%s-workloads" (include "telltale.fullname" .)) }}
{{- end }}
{{/* REQ: FLT-017 — an IPv4 CIDR's reverse zone, rounded to whole octets (10.42.0.0/16 →
42.10.in-addr.arpa). Empty for anything else. */}}
{{- define "telltale.reverseZone" -}}
{{- $parts := splitList "/" . }}
{{- if eq (len $parts) 2 }}
{{- $octets := splitList "." (index $parts 0) }}
{{- $keep := div (atoi (index $parts 1)) 8 }}
{{- if and (eq (len $octets) 4) (gt $keep 0) }}
{{- $rev := list }}
{{- range $i := until (int $keep) }}{{ $rev = prepend $rev (index $octets $i) }}{{ end }}
{{- printf "%s.in-addr.arpa" (join "." $rev) }}
{{- end }}
{{- end }}
{{- end }}
{{/* REQ: FLT-017 — TelltaleDNS's own pods ask CoreDNS, not their own Service: with the
kubelet's cluster DNS pointed at TelltaleDNS, they'd otherwise start by asking themselves. */}}
{{- define "telltale.podDns" -}}
{{- if and .Values.kubernetes.enabled .Values.kubernetes.ownPodsUseClusterDns }}
dnsPolicy: None
dnsConfig:
  nameservers: [{{ .Values.kubernetes.clusterDns | quote }}]
  searches:
    - {{ printf "%s.svc.%s" .Release.Namespace .Values.kubernetes.clusterDomain }}
    - {{ printf "svc.%s" .Values.kubernetes.clusterDomain }}
    - {{ .Values.kubernetes.clusterDomain }}
  options: [{ name: ndots, value: "5" }]
{{- else if .Values.hostNetwork }}
dnsPolicy: ClusterFirstWithHostNet
{{- end }}
{{- end }}
{{/* The controller's in-cluster cluster URL (what resolver pods join). */}}
{{- define "telltale.clusterURL" -}}
https://{{ include "telltale.fullname" . }}-cluster.{{ .Release.Namespace }}.svc:{{ .Values.cluster.port }}
{{- end }}
