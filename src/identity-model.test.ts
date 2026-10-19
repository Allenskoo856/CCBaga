/**
 * [INPUT]: 身份脱敏摘要与可控时钟。
 * [OUTPUT]: 旧摘要、未知期限、到期边界和本地元数据语义回归。
 * [POS]: 身份状态的纯函数测试，不读取凭据或联网验证账号。
 * [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
 */
import {test,expect} from 'bun:test';
import {credentialStatus} from './identity-model';
test('状态只表示可信本地元数据，到期不会继续显示未过期',()=>{
 expect(credentialStatus(null,100)).toBe('unknown');
 expect(credentialStatus({auth_status:'valid',expires_at:200},100)).toBe('unknown');
 for(const expires_at of [null,undefined,NaN,-1,Infinity,1.5])expect(credentialStatus({auth_status:'local_unexpired',expires_at},100)).toBe('unknown');
 expect(credentialStatus({auth_status:'local_unexpired',expires_at:200},100)).toBe('local_unexpired');
 expect(credentialStatus({auth_status:'local_unexpired',expires_at:200},200)).toBe('expired');
 expect(credentialStatus({auth_status:'refresh_available',expires_at:100},200)).toBe('refresh_available');
 expect(credentialStatus({auth_status:'api_key'},200)).toBe('api_key');
});
