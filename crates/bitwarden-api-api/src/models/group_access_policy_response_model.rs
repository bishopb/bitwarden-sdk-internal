/*
 * Bitwarden Internal API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: latest
 *
 * Generated by: https://openapi-generator.tech
 */

use serde::{Deserialize, Serialize};

use crate::models;

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct GroupAccessPolicyResponseModel {
    #[serde(rename = "object", skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(rename = "read", skip_serializing_if = "Option::is_none")]
    pub read: Option<bool>,
    #[serde(rename = "write", skip_serializing_if = "Option::is_none")]
    pub write: Option<bool>,
    #[serde(rename = "groupId", skip_serializing_if = "Option::is_none")]
    pub group_id: Option<uuid::Uuid>,
    #[serde(rename = "groupName", skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    #[serde(rename = "currentUserInGroup", skip_serializing_if = "Option::is_none")]
    pub current_user_in_group: Option<bool>,
}

impl GroupAccessPolicyResponseModel {
    pub fn new() -> GroupAccessPolicyResponseModel {
        GroupAccessPolicyResponseModel {
            object: None,
            read: None,
            write: None,
            group_id: None,
            group_name: None,
            current_user_in_group: None,
        }
    }
}