/*
 * Copyright (C) 2024 Igalia S.L. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "config.h"
#include "JSTrustedTypePolicy.h"

#include <JavaScriptCore/SlotVisitorInlines.h>

namespace WebCore {

template<typename Visitor>
void JSTrustedTypePolicy::visitAdditionalChildren(Visitor& visitor)
{
    if (auto createHTML = wrapped().options().createHTML)
        createHTML->visitJSFunction(visitor);
    if (auto createScript = wrapped().options().createScript)
        createScript->visitJSFunction(visitor);
    if (auto createScriptURL = wrapped().options().createScriptURL)
        createScriptURL->visitJSFunction(visitor);
}

DEFINE_VISIT_ADDITIONAL_CHILDREN(JSTrustedTypePolicy);

} // namespace WebCore
