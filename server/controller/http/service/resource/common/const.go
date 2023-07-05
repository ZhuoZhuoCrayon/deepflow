/*
 * Copyright (c) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

var HEADER_KEY_X_USER_TYPE = "X-User-Type"
var HEADER_KEY_X_USER_ID = "X-User-Id"

// TODO delete
var REDIS_KEY_PREFIX_DEEPFLOW = "deepflow_"
var REDIS_KEY_PREFIX_RESOURECE_API = "resource_api_"
var REDIS_KEY_PREFIX_DIMENSION_RESOURCE = "dimension_resource_"

var USER_TYPE_SUPER_ADMIN = 1
var USER_TYPE_ADMIN = 2
var USER_TYPE_TENANT = 5
var USER_TYPE_READ_ONLY_ADMIN = 10 // TODO verify permission
