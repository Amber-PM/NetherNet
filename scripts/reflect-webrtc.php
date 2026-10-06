<?php

declare(strict_types=1);

if(!extension_loaded('webrtc')){
	throw new RuntimeException('Load ext-webrtc before reflecting its API');
}

function renderType(?ReflectionType $type) : string{
	if($type === null){
		return '';
	}
	if(!$type instanceof ReflectionNamedType){
		throw new RuntimeException('Unexpected native type');
	}
	$name = $type->getName();
	return ($type->allowsNull() && $name !== 'mixed' ? '?' : '') . ($type->isBuiltin() ? $name : '\\' . $name);
}

echo "<?php\n\n// Generated from ext-webrtc ", phpversion('webrtc'), " linked to ", constant('pmmp\\webrtc\\WEBRTC_VERSION'), ".\n";
echo "// Static analysis only; never autoload or require this file.\nnamespace pmmp\\webrtc;\n";
foreach((new ReflectionExtension('webrtc'))->getClasses() as $class){
	echo "\n";
	if($class->isEnum()){
		/** @var class-string<UnitEnum> $enumClass */
		$enumClass = $class->getName();
		$enum = new ReflectionEnum($enumClass);
		echo 'enum ', $class->getShortName(), ': ', (string) $enum->getBackingType(), "{\n";
		foreach($enum->getCases() as $case){
			if(!$case instanceof ReflectionEnumBackedCase){
				throw new RuntimeException('Expected backed native enum');
			}
			echo "\tcase ", $case->getName(), ' = ', $case->getBackingValue(), ";\n";
		}
		echo "}\n";
		continue;
	}
	echo ($class->isFinal() ? 'final ' : ''), 'class ', $class->getShortName();
	$parent = $class->getParentClass();
	if($parent !== false){
		echo ' extends \\', $parent->getName();
	}
	echo "{\n";
	foreach($class->getMethods() as $method){
		if($method->getDeclaringClass()->getName() !== $class->getName()){
			continue;
		}
		echo "\t", $method->isPublic() ? 'public ' : 'private ', $method->isStatic() ? 'static ' : '', 'function ', $method->getName(), '(';
		$params = [];
		foreach($method->getParameters() as $param){
			$text = renderType($param->getType()) . ' ' . ($param->isVariadic() ? '...' : '') . '$' . $param->getName();
			if($param->isDefaultValueAvailable()){
				$default = $param->getDefaultValue();
				$text .= ' = ' . ($default instanceof UnitEnum ? '\\' . $default::class . '::' . $default->name : var_export($default, true));
			}
			$params[] = $text;
		}
		echo implode(', ', $params), ')';
		$return = renderType($method->getReturnType());
		echo $return === '' ? '' : ' : ' . $return, "{ throw new \\LogicException('Analysis only'); }\n";
	}
	echo "}\n";
}
