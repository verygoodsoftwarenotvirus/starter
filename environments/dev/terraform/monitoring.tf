#resource "google_monitoring_alert_policy" "unacked_pub_sub_messages_alert_policy" {
#  display_name = "Unacked Pub/Sub Messages"
#  combiner     = "OR"
#  conditions {
#    display_name = "Unacked Pub/Sub Messages"
#
#    condition_threshold {
#      filter     = "resource.type = \"pubsub_topic\" AND metric.type = \"pubsub.googleapis.com/topic/num_unacked_messages_by_region\""
#      duration   = "300s"
#      comparison = "COMPARISON_GT"
#      aggregations {
#        alignment_period   = "300s"
#        per_series_aligner = "ALIGN_COUNT"
#      }
#      trigger {
#        count = 1
#      }
#      threshold_value = 25
#    }
#  }
#
#  alert_strategy {
#    auto_close = "259200s"
#  }
#}

#resource "google_monitoring_alert_policy" "worker_memory_usage_alert_policy" {
#  display_name = "Workers Memory Usage"
#  combiner     = "OR"
#  conditions {
#    display_name = "Container Memory Utilization"
#
#    condition_threshold {
#      filter     = "resource.type = \"cloud_run_revision\" AND (resource.labels.service_name != \"api-server\" AND resource.labels.service_name != \"webapp-server\") AND metric.type = \"run.googleapis.com/container/memory/utilizations\""
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

