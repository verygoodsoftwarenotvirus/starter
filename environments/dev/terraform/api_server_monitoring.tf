#resource "google_monitoring_service" "api_service" {
#  service_id   = "api-service"
#  display_name = "API Service"
#
#  basic_service {
#    service_type = "CLOUD_RUN"
#    service_labels = {
#      service_name = google_cloud_run_v2_service.api_server.name
#      location     = local.gcp_region
#    }
#  }
#}

#resource "google_monitoring_uptime_check_config" "api_uptime" {
#  display_name = "api-server-uptime-check"
#  timeout      = "60s"
#  period       = "300s"
#
#  http_check {
#    path         = "/_meta_/ready"
#    port         = "443"
#    use_ssl      = true
#    validate_ssl = true
#  }
#
#  monitored_resource {
#    type = "uptime_url"
#    labels = {
#      project_id = local.project_id
#      host       = "api.whatever.dev"
#    }
#  }
#}

#resource "google_monitoring_notification_channel" "api_server_monitor_notification_channel" {
#  display_name = "API Service Monitor Notification Channel"
#  type         = "email"
#
#  labels = {
#    email_address = "verygoodsoftwarenotvirus@protonmail.com"
#  }
#}

#resource "google_monitoring_slo" "api_server_latency_slo" {
#  service = google_monitoring_service.api_service.service_id
#
#  slo_id          = "api-server-latency-slo"
#  goal            = 0.999
#  calendar_period = "DAY"
#  display_name    = "API Server Latency"
#
#  basic_sli {
#    latency {
#      threshold = "1s"
#    }
#  }
#}

#resource "google_monitoring_slo" "api_server_availability_slo" {
#  service = google_monitoring_service.api_service.service_id
#
#  slo_id          = "api-server-availability-slo"
#  goal            = 0.999
#  calendar_period = "DAY"
#  display_name    = "API Server Availability"
#
#  basic_sli {
#    availability {
#      enabled = true
#    }
#  }
#}

#resource "google_monitoring_alert_policy" "api_latency_alert_policy" {
#  display_name = "API Latency Alert Policy"
#  combiner     = "OR"
#
#  conditions {
#    display_name = "request latency"
#    condition_monitoring_query_language {
#      duration = ""
#      query    = <<END
#        fetch uptime_url
#        | metric 'monitoring.googleapis.com/uptime_check/request_latency'
#        | filter (metric.checked_resource_id == 'api.whatever.dev')
#        | group_by 5m, [value_request_latency_max: max(value.request_latency)]
#        | every 5m
#        | group_by [], [value_request_latency_max_max: max(value_request_latency_max)]
#        | group_by [],
#            [value_request_latency_max_max_mean: mean(value_request_latency_max_max)]
#        | condition val() > 999 'ms'
#      END
#    }
#  }
#}

#resource "google_monitoring_alert_policy" "latency_server_memory_usage_alert_policy" {
#  display_name = "API Server Memory Usage"
#  combiner     = "OR"
#  conditions {
#    display_name = "API Server Memory Utilization"
#
#    condition_threshold {
#      filter     = "resource.type = \"cloud_run_revision\" AND (resource.labels.service_name = \"api-server\") AND metric.type = \"run.googleapis.com/container/memory/utilizations\""
#      duration   = "300s"
#      comparison = "COMPARISON_GT"
#      aggregations {
#        alignment_period   = "300s"
#        per_series_aligner = "ALIGN_PERCENTILE_99"
#      }
#      trigger {
#        count = 1
#      }
#      threshold_value = 0.8
#    }
#  }
#
#  alert_strategy {
#    auto_close = "259200s"
#  }
#}
