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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "ContentSecurityPolicyTrustedTypesDirective.h"

#include "ContentSecurityPolicy.h"
#include "ContentSecurityPolicyDirectiveList.h"
#include "ParsingUtilities.h"
#include <wtf/text/StringCommon.h>

namespace {

bool isNotPolicyNameChar(UChar c)
{
    // This implements the negation of one char of tt-policy-name from
    // https://w3c.github.io/trusted-types/dist/spec/#trusted-types-csp-directive
    bool is_name_char = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') || c == '-' || c == '#' ||
                        c == '=' || c == '_' || c == '/' || c == '@' ||
                        c == '.' || c == '%';
    return !is_name_char;
}

bool isPolicyName(const String& name)
{
    // This implements tt-policy-name from
    // https://w3c.github.io/trusted-types/dist/spec/#trusted-types-csp-directive
    return name.find(&isNotPolicyNameChar) == notFound;
}

} //namespace

namespace WebCore {

template<typename CharacterType> static bool isTrustedTypesNone(StringParsingBuffer<CharacterType> buffer)
{
    skipWhile<isUnicodeCompatibleASCIIWhitespace>(buffer);

    if (!skipExactlyIgnoringASCIICase(buffer, "'none'"_s))
        return false;

    skipWhile<isUnicodeCompatibleASCIIWhitespace>(buffer);

    return buffer.atEnd();
}

template<typename CharacterType> static bool isTrustedTypeCharacter(CharacterType c)
{
    return !isUnicodeCompatibleASCIIWhitespace(c);
}

template<typename CharacterType> static bool isPolicyNameCharacter(CharacterType c)
{
    return isASCIIAlphanumeric(c) || c == '-' || c == '#' || c == '=' || c == '_' || c == '/' || c == '@' || c == '.' || c == '%';
}

ContentSecurityPolicyTrustedTypesDirective::ContentSecurityPolicyTrustedTypesDirective(const ContentSecurityPolicyDirectiveList& directiveList, const String& name, const String& value)
: ContentSecurityPolicyDirective(directiveList, name, value)
{
    parse(value);
}

bool ContentSecurityPolicyTrustedTypesDirective::allows(const String& value, bool isDuplicate, AllowTrustedTypePolicyDetails& details) const
{
    if (isDuplicate && !m_allowDuplicates) {
        details = AllowTrustedTypePolicyDetails::DisallowedDuplicateName;
    } else if (isDuplicate && value == "default"_s) {
        details = AllowTrustedTypePolicyDetails::DisallowedDuplicateName;
    } else if (!isPolicyName(value)) {
        details = AllowTrustedTypePolicyDetails::DisallowedName;
    } else if (!(m_allowAny || m_list.contains(value))) {
        details = AllowTrustedTypePolicyDetails::DisallowedName;
    } else {
        details = AllowTrustedTypePolicyDetails::Allowed;
    }
    return details == AllowTrustedTypePolicyDetails::Allowed;
}

void ContentSecurityPolicyTrustedTypesDirective::parse(const String& value)
{
    // 'trusted-types;'
    if (value.isEmpty()) {
        return;
    }

    readCharactersForParsing(value, [&](auto buffer) {
        if (isTrustedTypesNone(buffer)) {
            return;
        }

        while (buffer.hasCharactersRemaining()) {
            skipWhile<isUnicodeCompatibleASCIIWhitespace>(buffer);
            if (buffer.atEnd())
                return;

            auto beginPolicy = buffer.position();
            skipWhile<isTrustedTypeCharacter>(buffer);

            auto policyBuffer = StringParsingBuffer { beginPolicy, buffer.position() };

            if (skipExactlyIgnoringASCIICase(policyBuffer, "'allow-duplicates'"_s)) {
                m_allowDuplicates = true;
                continue;
            }

            if (skipExactlyIgnoringASCIICase(policyBuffer, "'none'"_s)) {
                directiveList().policy().reportInvalidTrustedTypesNoneKeyword();
                continue;
            }

            if (skipExactly(policyBuffer, '*')) {
                m_allowAny = true;
                continue;
            }

            if (skipExactly<isPolicyNameCharacter>(policyBuffer)) {
                auto policy = String(beginPolicy, buffer.position() - beginPolicy);
                m_list.add(policy);
            } else {
                auto policy = String(beginPolicy, buffer.position() - beginPolicy);
                directiveList().policy().reportInvalidTrustedTypesPolicy(policy);
            }

            ASSERT(buffer.atEnd() || isUnicodeCompatibleASCIIWhitespace(*buffer));
        }
    });
}

} // namespace WebCore
