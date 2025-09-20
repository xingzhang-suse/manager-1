package com.neu.utils

/**
 * Created by Steven Zhang on 9/19/21.
 */
object MathUtils {
  def digitLength2Int(digitStr: String): Int = {
    val pattern = "(?i)(\\d+)([kMG]?)".r
    digitStr.trim match {
      case pattern(num, unit) =>
        val base = num.toInt
        unit.toLowerCase match {
          case ""  => base
          case "k" => base * 1024
          case "M" => base * 1024 * 1024
          case "G" => base * 1024 * 1024 * 1024
          case _   => throw new IllegalArgumentException(s"Unsupported unit: $unit")
        }
      case _                  => throw new IllegalArgumentException(s"Invalid format: $digitStr")
    }
  }

}
