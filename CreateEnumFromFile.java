//Parse a txt file to create an enum from a file, currently only designed for enums from 010 bts
//@author Reichard
//@category Data
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;

public class CreateEnumFromFile extends GhidraScript {

	@Override
	protected void run() throws Exception {
		File file = askFile("","OK");
		if(!file.exists() || !file.canRead() || !file.isFile()) {
			println("File error, exiting");
			return;
		} else if(!file.getName().endsWith(".txt")) {
			println("File is not a supported format");
			return;
		}
		addEnum(file);
	}
	
	public void addEnum(File file) throws IOException {
		try(BufferedReader br = new BufferedReader(new FileReader(file))){
			Pattern enumHeader = Pattern.compile("^enum<([a-zA-Z0-9_]+)>\\s+([a-zA-Z0-9_]+)\\s*\\{");
			Pattern enumData = Pattern.compile("^\\s*\\t*([a-zA-Z0-9_]+)\\s?(?:\\s*=\\s*(\\d+))?\\s*,?\\s*$");
			Matcher m;
			String line;
			line = br.readLine();
			//first line
			if(line==null) return;
			m = enumHeader.matcher(line);
			if(!m.find()) return;
			String dataType = m.group(1);
			int dataSize = DataType.getSizeFromString(dataType);
			if(dataSize==-1) {
				print("data type of enum is not supported, add it yourself");
				return;
			}
			String enumName = m.group(2);
			
			CategoryPath categoryPath = new CategoryPath("/enums");
			EnumDataType NewEnum = new EnumDataType(categoryPath,enumName,dataSize);
			
			//data
			int index=0;
			while ((line = br.readLine()) != null && (m = enumData.matcher(line))!=null && !line.contains("}") && m.find() ) {
				if(m.group(2)!=null)
					index=Integer.parseInt(m.group(2));
				String entry = String.format("%d - %s", index,m.group(1));
				print(entry);
				NewEnum.add(entry, index++);
			}
			DataTypeManager dtm = currentProgram.getDataTypeManager();
			dtm.addDataType(NewEnum, null);
		}
	}

	public enum DataType{
		BYTE("byte",1),
		UBYTE("uint",1),
		UINT("uint",4),
		INT("int",4),
		SHORT("short",2),
		USHORT("ushort",2),
		LONG("long",8),
		ULONG("ulong",8);

		private final String name;
		private final int size;
		
		DataType(String string, int i) {
			this.name = string;
			this.size = i;
		}
		
		public static int getSizeFromString(String dataTypeName) {
			for(DataType dt : values()) {
				if(dt.name.equals(dataTypeName)) {
					return dt.size;
				}
			}
			return -1;
		}
	}
}
