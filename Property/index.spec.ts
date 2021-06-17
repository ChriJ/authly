import * as authly from "../index"

authly.Issuer.defaultIssuedAt = new Date("1970-01-01T13:37:42.000Z")

describe("property", () => {
	const transformers: (authly.Property.Transformer | undefined)[] = [
		new authly.Property.Converter({
			expires: {
				forward: (value: string) => Math.floor(new Date(value).valueOf() / 1000),
				backward: (value: number) => new Date(value * 1000).toISOString(),
			},
			issued: {
				forward: (value: string) => Math.floor(new Date(value).valueOf() / 1000),
				backward: (value: number) => new Date(value * 1000).toISOString(),
			},
		}),
		new authly.Property.Renamer({ issuer: "iss", issued: "iat", expires: "exp", backend: "bkd" }),
	]

	it("get original names", async () => {
		const algorithm = authly.Algorithm.RS256(
			"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQAB",
			"MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjskFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0goamMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5YlSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNpbU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9BBwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjxQYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5Ky18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrBjg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE="
		)

		const verifier = authly.Verifier.create(algorithm).add(...transformers)
		if (verifier) {
			const verification = await verifier.verify(
				"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiaWF0IjoxNTgzMTAzNjAwLCJia2QiOiJhYmMuZGVmLmdoaWoiLCJleHAiOjE2MjUwOTc2MDB9.IRPWJVn1sgeMAuBAsIapRoSSO59BmaXPE8JQJqY3aTkTI6DEwc17Lterj9xRLSOqM66tMzCJh7yXcVPWGyzn03FnrzlPbAQxwSDZOJgn2_zD7fnY43KWtedRENRna8fq-Sre34lrp3bTNqsIdaFU20YVqm9zozhC9hlD1CtIYTQ0IUmIN7k2To1qyXQ8RnKzxQ8S3dehC1-hmW5xlWpz9Ne2rFr3wWUocUvPruoNMz5zsk5L_it0XeyxalOFvjkl7MGAzv0PHxh9pFhzDf1tqLXzG21rhOAo6VjUctTF5TdKzb-s0wAGS0gsS6uGz5APzlKndcwCXBvbiF-hDEMvWg"
			)
			expect(verification).toEqual({
				backend: "abc.def.ghij",
				expires: "2021-07-01T00:00:00.000Z",
				issued: "2020-03-01T23:00:00.000Z",
				issuer: "test",
				token:
					"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiaWF0IjoxNTgzMTAzNjAwLCJia2QiOiJhYmMuZGVmLmdoaWoiLCJleHAiOjE2MjUwOTc2MDB9.IRPWJVn1sgeMAuBAsIapRoSSO59BmaXPE8JQJqY3aTkTI6DEwc17Lterj9xRLSOqM66tMzCJh7yXcVPWGyzn03FnrzlPbAQxwSDZOJgn2_zD7fnY43KWtedRENRna8fq-Sre34lrp3bTNqsIdaFU20YVqm9zozhC9hlD1CtIYTQ0IUmIN7k2To1qyXQ8RnKzxQ8S3dehC1-hmW5xlWpz9Ne2rFr3wWUocUvPruoNMz5zsk5L_it0XeyxalOFvjkl7MGAzv0PHxh9pFhzDf1tqLXzG21rhOAo6VjUctTF5TdKzb-s0wAGS0gsS6uGz5APzlKndcwCXBvbiF-hDEMvWg",
			})
		}
	})
})
