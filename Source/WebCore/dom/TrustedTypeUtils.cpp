/*
 * Copyright (C) 2024 Igalia S.L. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "TrustedTypeUtils.h"

#include "WindowOrWorkerGlobalScopeTrustedTypes.h"
#include "WorkerGlobalScope.h"
#include <JavaScriptCore/HeapInlines.h>
#include <JavaScriptCore/JSCInlines.h>
#include <JavaScriptCore/JSCJSValueInlines.h>
#include <JavaScriptCore/JSCast.h>

namespace WebCore {
using namespace JSC;

struct TrustedTypeVisitor {
    String operator()(std::nullptr_t)
    {
        return nullString();
    }
    String operator()(Ref<TrustedHTML> value)
    {
        return value->toString();
    }
    String operator()(Ref<TrustedScript> value)
    {
        return value->toString();
    }
    String operator()(Ref<TrustedScriptURL> value)
    {
        return value->toString();
    }
};

// https://w3c.github.io/trusted-types/dist/spec/#process-value-with-a-default-policy-algorithm
std::variant<std::nullptr_t, Ref<TrustedHTML>, Ref<TrustedScript>, Ref<TrustedScriptURL>> processValueWithDefaultPolicy(ScriptExecutionContext& scriptExecutionContext, const String& expectedType, const String& input, const String& sink)
{
    VM& vm = scriptExecutionContext.vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    RefPtr<TrustedTypePolicy> protector = nullptr;
    if (RefPtr document = dynamicDowncast<Document>(scriptExecutionContext)) {
        if (auto window = document->domWindow()) {
            auto trustedTypesFactory = WindowOrWorkerGlobalScopeTrustedTypes::trustedTypes(*window);
            protector = trustedTypesFactory->defaultPolicy();
        }
    } else if (RefPtr workerGlobalScope = dynamicDowncast<WorkerGlobalScope>(scriptExecutionContext)) {
        auto trustedTypesFactory = WindowOrWorkerGlobalScopeTrustedTypes::trustedTypes(*workerGlobalScope);
        protector = trustedTypesFactory->defaultPolicy();
    }

    if (!protector)
        return nullptr;

    JSC::JSLockHolder locker(vm);
    auto jsExpectedType = JSC::jsStringWithCache(vm, expectedType);
    JSC::Strong<JSC::Unknown> strongExpectedType(vm, jsExpectedType);
    auto jsSink = JSC::jsStringWithCache(vm, sink);
    JSC::Strong<JSC::Unknown> strongSink(vm, jsSink);
    FixedVector<JSC::Strong<JSC::Unknown>> arguments({ strongExpectedType, strongSink });
    auto policyValueHolder = protector->getPolicyValue(expectedType, input, WTFMove(arguments), false);
    if (policyValueHolder.hasException()) {
        propagateException(*scriptExecutionContext.globalObject(), scope, policyValueHolder.releaseException());
        return nullptr;
    }

    auto policyValue = policyValueHolder.releaseReturnValue();
    if (policyValue.isNull())
        return nullptr;

    std::variant<std::nullptr_t, Ref<TrustedHTML>, Ref<TrustedScript>, Ref<TrustedScriptURL>> result;
    if (expectedType == "TrustedHTML"_s) {
        result.emplace<1>(TrustedHTML::create(policyValue));
        return result;
    }
    if (expectedType == "TrustedScript"_s) {
        result.emplace<2>(TrustedScript::create(policyValue));
        return result;
    }
    if (expectedType == "TrustedScriptURL"_s) {
        result.emplace<3>(TrustedScriptURL::create(policyValue));
        return result;
    }

    ASSERT_NOT_REACHED();
    return nullptr;
}

// https://w3c.github.io/trusted-types/dist/spec/#get-trusted-type-compliant-string-algorithm
String getTrustedTypeCompliantString(const String& expectedType, ScriptExecutionContext& scriptExecutionContext, const String& value, const String& sink)
{
    VM& vm = scriptExecutionContext.vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    auto contentSecurityPolicy = scriptExecutionContext.contentSecurityPolicy();

    auto requireTrustedTypes = contentSecurityPolicy
    ? contentSecurityPolicy->requireTrustedTypesForSinkGroup("script"_s)
    : false;

    String stringValue(value);

    if (requireTrustedTypes && scriptExecutionContext.settingsValues().trustedTypesEnabled) {
        std::variant<std::nullptr_t, Ref<TrustedHTML>, Ref<TrustedScript>, Ref<TrustedScriptURL>> convertedType = processValueWithDefaultPolicy(scriptExecutionContext, expectedType, stringValue, sink);
        RETURN_IF_EXCEPTION(scope, { });

        if (!std::holds_alternative<std::nullptr_t>(convertedType)) {
            auto dataString = std::visit(TrustedTypeVisitor { }, convertedType);
            stringValue = dataString;
            if (dataString.isNull())
                convertedType = nullptr;
        }

        if (std::holds_alternative<std::nullptr_t>(convertedType)) {
            auto required = !contentSecurityPolicy->allowMissingTrustedTypesForSinkGroup(expectedType, sink, "script"_s, stringValue);

            if (required) {
                JSC::JSLockHolder locker(vm);
                throwTypeError(scriptExecutionContext.globalObject(), scope, makeString("This assignment requires a ", expectedType));
            }
        }
    }

    return stringValue;
}

} // namespace WebCore
