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

#include "ContentSecurityPolicy.h"
#include "Document.h"
#include "JSDOMExceptionHandling.h"
#include "TrustedTypePolicy.h"
#include "TrustedTypePolicyFactory.h"
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
    String operator()(Exception)
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

String trustedTypeToString(const TrustedType trustedType)
{
    switch (trustedType) {
    case TrustedType::TrustedHTML:
        return "TrustedHTML"_s;
    case TrustedType::TrustedScript:
        return "TrustedScript"_s;
    case TrustedType::TrustedScriptURL:
        return "TrustedScriptURL"_s;
    default:
        ASSERT_NOT_REACHED();
        return nullString();
    }
}

// https://w3c.github.io/trusted-types/dist/spec/#process-value-with-a-default-policy-algorithm
std::variant<std::nullptr_t, Exception, Ref<TrustedHTML>, Ref<TrustedScript>, Ref<TrustedScriptURL>> processValueWithDefaultPolicy(ScriptExecutionContext& scriptExecutionContext, TrustedType expectedType, const String& input, const String& sink)
{
    RefPtr<TrustedTypePolicy> protectedPolicy;
    if (RefPtr document = dynamicDowncast<Document>(scriptExecutionContext)) {
        if (auto window = document->domWindow()) {
            auto trustedTypesFactory = WindowOrWorkerGlobalScopeTrustedTypes::trustedTypes(*window);
            protectedPolicy = trustedTypesFactory->defaultPolicy();
        }
    } else if (RefPtr workerGlobalScope = dynamicDowncast<WorkerGlobalScope>(scriptExecutionContext)) {
        auto trustedTypesFactory = WindowOrWorkerGlobalScopeTrustedTypes::trustedTypes(*workerGlobalScope);
        protectedPolicy = trustedTypesFactory->defaultPolicy();
    }

    if (!protectedPolicy)
        return nullptr;

    VM& vm = scriptExecutionContext.vm();

    auto jsExpectedType = JSC::jsString(vm, trustedTypeToString(expectedType));
    JSC::Strong<JSC::Unknown> strongExpectedType(vm, jsExpectedType);
    auto jsSink = JSC::jsString(vm, sink);
    JSC::Strong<JSC::Unknown> strongSink(vm, jsSink);
    FixedVector<JSC::Strong<JSC::Unknown>> arguments({ strongExpectedType, strongSink });
    auto policyValueHolder = protectedPolicy->getPolicyValue(expectedType, input, WTFMove(arguments), false);
    if (policyValueHolder.hasException())
        return { policyValueHolder.releaseException() };

    auto policyValue = policyValueHolder.releaseReturnValue();
    if (policyValue.isNull())
        return nullptr;

    if (expectedType == TrustedType::TrustedHTML)
        return { TrustedHTML::create(policyValue) };
    if (expectedType == TrustedType::TrustedScript)
        return { TrustedScript::create(policyValue) };
    if (expectedType == TrustedType::TrustedScriptURL)
        return { TrustedScriptURL::create(policyValue) };

    ASSERT_NOT_REACHED();
    return nullptr;
}

// https://w3c.github.io/trusted-types/dist/spec/#get-trusted-type-compliant-string-algorithm
ExceptionOr<String> getTrustedTypeCompliantString(TrustedType expectedType, ScriptExecutionContext& scriptExecutionContext, const String& input, const String& sink)
{
    String stringValue(input);

    if (!scriptExecutionContext.settingsValues().trustedTypesEnabled)
        return stringValue;

    CheckedPtr contentSecurityPolicy = scriptExecutionContext.checkedContentSecurityPolicy();

    auto requireTrustedTypes = contentSecurityPolicy
        ? contentSecurityPolicy->requireTrustedTypesForSinkGroup("script"_s)
        : false;

    if (!requireTrustedTypes)
        return stringValue;

    auto convertedInput = processValueWithDefaultPolicy(scriptExecutionContext, expectedType, stringValue, sink);
    if (std::holds_alternative<Exception>(convertedInput))
        return WTFMove(std::get<Exception>(convertedInput));

    if (!std::holds_alternative<std::nullptr_t>(convertedInput)) {
        stringValue = std::visit(TrustedTypeVisitor { }, convertedInput);
        if (stringValue.isNull())
            convertedInput = nullptr;
    }

    if (std::holds_alternative<std::nullptr_t>(convertedInput)) {
        auto allowMissingTrustedTypes = contentSecurityPolicy->allowMissingTrustedTypesForSinkGroup(trustedTypeToString(expectedType), sink, "script"_s, stringValue);

        if (!allowMissingTrustedTypes)
            return Exception { ExceptionCode::TypeError, makeString("This assignment requires a ", trustedTypeToString(expectedType)) };
    }

    return stringValue;
}

} // namespace WebCore
