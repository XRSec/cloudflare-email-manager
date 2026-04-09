import api, { get, type ApiResponse } from './api-client'
import { systemApiService } from './api-system'
import { userApiService } from './api-user'
import { authApiService } from './api-auth'
import { emailApiService } from './api-email'
import { adminApiService } from './api-admin'
import { toolsApiService } from './api-tools'

export { api, get, type ApiResponse }
export { systemApiService } from './api-system'
export { userApiService } from './api-user'
export { authApiService } from './api-auth'
export { emailApiService } from './api-email'
export { adminApiService } from './api-admin'
export { toolsApiService } from './api-tools'

export const apiService = {
  ...systemApiService,
  ...userApiService,
  ...authApiService,
  ...emailApiService,
  ...adminApiService,
  ...toolsApiService,
  getEmails: emailApiService.getEmails,
  getEmail: emailApiService.getEmail,
  deleteEmail: emailApiService.deleteEmail,
  batchDeleteEmails: emailApiService.batchDeleteEmails,
  updateEmailReadStatus: emailApiService.updateEmailReadStatus,
  batchUpdateEmailReadStatus: emailApiService.batchUpdateEmailReadStatus,
  sendEmail: emailApiService.sendEmail
}

export default api
